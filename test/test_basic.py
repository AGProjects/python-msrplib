from __future__ import with_statement
import sys
import unittest
import new
import pprint
from copy import copy

from twisted.internet.error import ConnectionDone, ConnectionClosed
from twisted.names.srvconnect import SRVConnector
from twisted.internet import reactor

from gnutls.errors import GNUTLSError
from gnutls.crypto import X509PrivateKey, X509Certificate
from gnutls.interfaces.twisted import X509Credentials

from application import log
log.level.current = log.level.DEBUG

from eventlet import api
from eventlet.coros import event
from eventlet import proc

from msrplib.connect import get_connector, get_acceptor, MSRPRelaySettings, ConnectBase
from msrplib import protocol as pr
from msrplib.trafficlog import TrafficLogger, StateLogger, hook_std_output
from msrplib.transport import MSRPTransport
from msrplib.session import MSRPSession, MSRPSessionError

# add tell() method to stdout (needed by TrafficLogger)
hook_std_output()

class NoisySRVConnector(SRVConnector):

    def pickServer(self):
        host, port = SRVConnector.pickServer(self)
        print 'Resolved _%s._%s.%s --> %s:%s' % (self.service, self.protocol, self.domain, host, port)
        return host, port

ConnectBase.SRVConnectorClass = NoisySRVConnector

class TimeoutEvent(event):
    timeout = 10

    def wait(self):
        with api.timeout(self.timeout):
            return event.wait(self)

def _connect_msrp(local_event, remote_event, msrp, local_uri):
    full_local_path = msrp.prepare(local_uri)
    try:
        local_event.send(full_local_path)
        full_remote_path = remote_event.wait()
        result = msrp.complete(full_remote_path)
        assert isinstance(result, MSRPTransport), repr(result)
        return result
    finally:
        msrp.cleanup()

class MSRPSession_ZeroTimeout(MSRPSession):
    RESPONSE_TIMEOUT = 0

class InjectedError(Exception):
    pass

class TestBase(unittest.TestCase):
    server_relay = None
    client_relay = None
    client_traffic_logger = None
    client_state_logger = StateLogger(prefix='C ')
    server_traffic_logger = None
    server_state_logger = StateLogger(prefix='S ')
    PER_TEST_TIMEOUT = 30
    RESPONSE_TIMEOUT = 10
    debug = True
    use_tls = False # XXX how does it manage to work through relay then?
    server_credentials = None

    def setup_two_endpoints(self, clientMSRPTransport=MSRPTransport, serverMSRPTransport=MSRPTransport):
        server_path = TimeoutEvent()
        client_path = TimeoutEvent()

        client_uri = pr.URI(use_tls=self.use_tls)
        server_uri = pr.URI(port=0, use_tls=self.use_tls, credentials=self.server_credentials)

        def client():
            msrp = get_connector(relay=self.client_relay,
                                 traffic_logger=self.client_traffic_logger,
                                 state_logger=self.client_state_logger,
                                 MSRPTransportClass=clientMSRPTransport)
            return _connect_msrp(client_path, server_path, msrp, client_uri)

        def server():
            msrp = get_acceptor(relay=self.server_relay,
                                traffic_logger=self.server_traffic_logger,
                                state_logger=self.server_state_logger,
                                MSRPTransportClass=serverMSRPTransport)
            return _connect_msrp(server_path, client_path, msrp, server_uri)

        client = proc.spawn_link_exception(client)
        server = proc.spawn_link_exception(server)
        return client, server

    def setUp(self):
        print '\n' + self.__class__.__name__
        self.timer = api.exc_after(self.PER_TEST_TIMEOUT, api.TimeoutError('per test timeout expired'))

    def tearDown(self):
        self.timer.cancel()
        del self.timer

    def assertHeaderEqual(self, header, chunk1, chunk2):
        self.assertEqual(chunk1.headers[header].decoded, chunk2.headers[header].decoded)

    def assertSameData(self, chunk1, chunk2):
        try:
            self.assertHeaderEqual('Content-Type', chunk1, chunk2)
            self.assertEqual(chunk1.data, chunk2.data)
            self.assertEqual(chunk1.contflag, chunk2.contflag)
        except Exception:
            print 'Error while comparing %r and %r' % (chunk1, chunk2)
            raise


class MSRPTransportTest(TestBase):

    def _make_hello(self, msrp):
        x = msrp.make_chunk(data='hello')
        x.add_header(pr.ContentTypeHeader('text/plain'))
        # because MSRPTransport does not send thje responses, the relay must not either
        x.add_header(pr.FailureReportHeader('no'))
        return x

    def _send_chunk(self, sender, receiver):
        x = self._make_hello(sender)
        sender.write(x.encode())
        y = receiver.read_chunk()
        self.assertSameData(x, y)

    def test_send_chunk(self):
        client, server = proc.waitall(self.setup_two_endpoints())
        self._send_chunk(client, server)
        self._send_chunk(server, client)
        #self.assertNoIncoming(0.1, client, server)
        client.loseConnection()
        server.loseConnection()

    def test_close_connection__read(self):
        client, server = proc.waitall(self.setup_two_endpoints())
        client.loseConnection()
        self.assertRaises(ConnectionDone, server.read_chunk)
        self.assertRaises(ConnectionDone, server.write, self._make_hello(server).encode())
        self.assertRaises(ConnectionDone, client.read_chunk)
        self.assertRaises(ConnectionDone, client.write, self._make_hello(client).encode())

# add test for chunking

class TLSMixin(object):
    use_tls = True
    cert = X509Certificate(open('valid.crt').read())
    key = X509PrivateKey(open('valid.key').read())
    server_credentials = X509Credentials(cert, key)

class MSRPTransportTest_TLS(TLSMixin, MSRPTransportTest):
    pass

class MSRPSessionTest(TestBase):

    def deliver_chunk(self, msrp, chunk):
        e = event()
        msrp.send_chunk(chunk, e)
        with api.timeout(self.RESPONSE_TIMEOUT, api.TimeoutError('Did not received transaction response')):
            response = e.wait()
        return response

    def _make_hello(self, session):
        x = session.msrp.make_chunk(data='hello')
        x.add_header(pr.ContentTypeHeader('text/plain'))
        return x

    def _test_deliver_chunk(self, sender, receiver):
        x = self._make_hello(sender)
        response = self.deliver_chunk(sender, x)
        assert response.code == 200, response
        y = receiver.receive_chunk()
        self.assertSameData(x, y)

    def test_deliver_chunk(self):
        client, server = proc.waitall(self.setup_two_endpoints())
        client, server = MSRPSession(client), MSRPSession(server)
        self._test_deliver_chunk(client, server)
        self._test_deliver_chunk(server, client)
        #self.assertNoIncoming(0.1, client, server)
        client.shutdown()
        server.shutdown()

    def test_send_chunk_response_localtimeout(self):
        client, server = proc.waitall(self.setup_two_endpoints())
        client, server = MSRPSession_ZeroTimeout(client), MSRPSession(server)
        x = self._make_hello(client)
        response = self.deliver_chunk(client, x)
        assert response.code == 408, response
        y = server.receive_chunk()
        self.assertSameData(x, y)
        #self.assertNoIncoming(0.1, client, server)
        server.shutdown()
        client.shutdown()

    def test_close_connection__receive(self):
        client, server = proc.waitall(self.setup_two_endpoints())
        assert isinstance(client, MSRPTransport), repr(client)
        client, server = MSRPSession(client), MSRPSession(server)
        client.shutdown()
        self.assertRaises(ConnectionDone, server.receive_chunk)
        self.assertRaises(MSRPSessionError, server.send_chunk, self._make_hello(server))
        self.assertRaises(ConnectionDone, client.receive_chunk)
        self.assertRaises(MSRPSessionError, client.send_chunk, self._make_hello(client))

    def test_reader_failed__receive(self):
        # if reader fails with an exception, receive_chunk raises that exception
        # send_chunk raises an error and the other party gets closed connection
        client, server = proc.waitall(self.setup_two_endpoints())
        client, server = MSRPSession(client), MSRPSession(server)
        client.reader_job.kill(InjectedError("Killing client's reader_job"))
        self.assertRaises(InjectedError, client.receive_chunk)
        self.assertRaises(MSRPSessionError, client.send_chunk, self._make_hello(client))
        self.assertRaises(ConnectionClosed, server.receive_chunk)
        self.assertRaises(MSRPSessionError, server.send_chunk, self._make_hello(server))

    def test_reader_failed__send(self):
        client, server = proc.waitall(self.setup_two_endpoints())
        client, server = MSRPSession(client), MSRPSession(server)
        client.reader_job.kill(InjectedError("Killing client's reader_job"))
        api.sleep(0.1)
        self.assertRaises(MSRPSessionError, client.send_chunk, self._make_hello(client))
        self.assertRaises(InjectedError, client.receive_chunk)
        api.sleep(0.1)
        self.assertRaises(MSRPSessionError, server.send_chunk, self._make_hello(server))
        self.assertRaises(ConnectionClosed, server.receive_chunk)

class MSRPSessionTest_TLS(TLSMixin, MSRPSessionTest):
    pass


from optparse import OptionParser
parser = OptionParser()
parser.add_option('--domain')
parser.add_option('--username')
parser.add_option('--password')
parser.add_option('--host')
parser.add_option('--port', default=2855)
parser.add_option('--log-client', action='store_true', default=False)
parser.add_option('--log-server', action='store_true', default=False)
parser.add_option('--debug', action='store_true', default=False)
options, _args = parser.parse_args()

StateLogger.debug = options.debug

if options.log_client:
    TestBase.client_traffic_logger = TrafficLogger.to_file(prefix='C ')
if options.log_server:
    TestBase.server_traffic_logger = TrafficLogger.to_file(prefix='S ')

relays = []
# SRV:
if options.domain is not None:
    relays.append(MSRPRelaySettings(options.domain, options.username, options.password))
# explicit host:
if options.host is not None:
    assert options.domain is not None
    relays.append(MSRPRelaySettings(options.domain, options.username, options.password, options.host, options.port))

configs = []
for relay in relays:
    configs.append({'server_relay': relay, 'client_relay': None})
    configs.append({'server_relay': relay, 'client_relay': relay})

def get_config_name(config):
    result = []
    for name, relay in config.items():
        if relay is not None:
            x = name
            print name, relay.host
            if relay.host is None:
                x += '_srv'
            result.append(x)
    return '_'.join(result)

def make_tests_for_other_configurations(TestClass):
    klass = TestClass.__name__
    for config in configs:
        config_name = get_config_name(config)
        klass_name = klass + '_' + config_name
        while klass_name in globals():
            klass_name += '_x'
        new_class = new.classobj(klass_name, (TestClass, ), copy(config))
        print klass_name
        globals()[klass_name] = new_class

if relays:
    print 'Relays: '
    pprint.pprint(relays)
    print
if configs:
    print 'Configs: '
    pprint.pprint(configs)
    print

make_tests_for_other_configurations(MSRPTransportTest)
make_tests_for_other_configurations(MSRPSessionTest)


if __name__=='__main__':
    test = unittest.defaultTestLoader.loadTestsFromModule(sys.modules['__main__'])
    testRunner = unittest.TextTestRunner().run(test)

