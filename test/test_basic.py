# Copyright (C) 2008-2009 AG Projects. See LICENSE for details

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

from eventlet import api
from eventlet.coros import event
from eventlet import proc

from msrplib.connect import get_connector, get_acceptor, MSRPRelaySettings, ConnectBase, MSRPServer
from msrplib import protocol as pr
from msrplib.trafficlog import TrafficLogger, Logger, hook_std_output
from msrplib.transport import MSRPTransport
from msrplib.session import GreenMSRPSession, MSRPSessionError, LocalResponse

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

class GreenMSRPSession_ZeroTimeout(GreenMSRPSession):
    RESPONSE_TIMEOUT = 0

class InjectedError(Exception):
    pass

class TestBase(unittest.TestCase):
    PER_TEST_TIMEOUT = 30
    client_relay = None
    client_logger = Logger(prefix='C ')
    server_relay = None
    server_logger = Logger(prefix='S ')
    debug = True
    use_tls = False
    server_credentials = None

    def get_client_uri(self):
        return pr.URI(use_tls=self.use_tls)

    def get_server_uri(self):
        return pr.URI(port=0, use_tls=self.use_tls, credentials=self.server_credentials)

    def get_connector(self):
        return get_connector(relay=self.client_relay, logger=self.client_logger)

    def get_acceptor(self):
        return get_acceptor(relay=self.server_relay, logger=self.server_logger)

    def setup_two_endpoints(self):
        server_path = TimeoutEvent()
        client_path = TimeoutEvent()
        client = proc.spawn_link_exception(_connect_msrp, client_path, server_path, self.get_connector(), self.get_client_uri())
        server = proc.spawn_link_exception(_connect_msrp, server_path, client_path, self.get_acceptor(), self.get_server_uri())
        return client, server

    def setUp(self):
        print '\n%s.%s' % (self.__class__.__name__, self._testMethodName)
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

    def make_hello(self, msrptransport, success_report=None, failure_report=None):
        chunk = msrptransport.make_chunk(data='hello')
        chunk.add_header(pr.ContentTypeHeader('text/plain'))
        # because MSRPTransport does not send the responses, the relay must not either
        if success_report is not None:
            chunk.add_header(pr.SuccessReportHeader(success_report))
        if failure_report is not None:
            chunk.add_header(pr.FailureReportHeader(failure_report))
        return chunk

    def _test_write_chunk(self, sender, receiver):
        chunk = self.make_hello(sender, failure_report='no')
        sender.write(chunk.encode())
        chunk_received = receiver.read_chunk()
        self.assertSameData(chunk, chunk_received)


class TLSMixin(object):
    use_tls = True
    cert = X509Certificate(open('valid.crt').read())
    key = X509PrivateKey(open('valid.key').read())
    server_credentials = X509Credentials(cert, key)


class MSRPTransportTest(TestBase):

    def test_write_chunk(self):
        client, server = proc.waitall(self.setup_two_endpoints())
        self._test_write_chunk(client, server)
        self._test_write_chunk(server, client)
        #self.assertNoIncoming(0.1, client, server)
        client.loseConnection()
        server.loseConnection()

    def test_close_connection__read(self):
        client, server = proc.waitall(self.setup_two_endpoints())
        client.loseConnection()
        self.assertRaises(ConnectionDone, server.read_chunk)
        self.assertRaises(ConnectionDone, server.write, self.make_hello(server).encode())
        self.assertRaises(ConnectionDone, client.read_chunk)
        self.assertRaises(ConnectionDone, client.write, self.make_hello(client).encode())

# add test for chunking


class MSRPTransportTest_TLS(TLSMixin, MSRPTransportTest):
    pass

class MSRPSessionTest(TestBase):

    def _test_deliver_chunk(self, sender, receiver, chunk=None):
        if chunk is None:
            chunk = self.make_hello(sender.msrp)
        response = sender.deliver_chunk(chunk)
        assert response.code == 200, response
        chunk_received = receiver.receive_chunk()
        self.assertSameData(chunk, chunk_received)

    def test_deliver_chunk(self):
        client, server = proc.waitall(self.setup_two_endpoints())
        client, server = GreenMSRPSession(client), GreenMSRPSession(server)
        self._test_deliver_chunk(client, server)
        self._test_deliver_chunk(server, client)
        #self.assertNoIncoming(0.1, client, server)
        client.shutdown()
        server.shutdown()

    def assertRaisesCode(self, exception, code, func, *args, **kwargs):
        try:
            func(*args, **kwargs)
        except exception, ex:
            self.assertEqual(ex.code, code)
        else:
            raise AssertionError('%r didnt raise %s' % (func, exception))

    def test_send_chunk_response_localtimeout(self):
        client, server = proc.waitall(self.setup_two_endpoints())
        client, server = GreenMSRPSession_ZeroTimeout(client), GreenMSRPSession(server)
        x = self.make_hello(client.msrp)
        self.assertRaisesCode(LocalResponse, 408, client.deliver_chunk, x)
        y = server.receive_chunk()
        self.assertSameData(x, y)
        #self.assertNoIncoming(0.1, client, server)
        server.shutdown()
        client.shutdown()

    def test_close_connection__receive(self):
        client, server = proc.waitall(self.setup_two_endpoints())
        assert isinstance(client, MSRPTransport), repr(client)
        client, server = GreenMSRPSession(client), GreenMSRPSession(server)
        client.shutdown()
        self.assertRaises(ConnectionDone, server.receive_chunk)
        self.assertRaises(MSRPSessionError, server.send_chunk, self.make_hello(server.msrp))
        self.assertRaises(ConnectionDone, client.receive_chunk)
        self.assertRaises(MSRPSessionError, client.send_chunk, self.make_hello(client.msrp))

    def test_reader_failed__receive(self):
        # if reader fails with an exception, receive_chunk raises that exception
        # send_chunk raises an error and the other party gets closed connection
        client, server = proc.waitall(self.setup_two_endpoints())
        client, server = GreenMSRPSession(client), GreenMSRPSession(server)
        client.reader_job.kill(InjectedError("Killing client's reader_job"))
        self.assertRaises(InjectedError, client.receive_chunk)
        self.assertRaises(MSRPSessionError, client.send_chunk, self.make_hello(client.msrp))
        self.assertRaises(ConnectionClosed, server.receive_chunk)
        self.assertRaises(MSRPSessionError, server.send_chunk, self.make_hello(server.msrp))

    def test_reader_failed__send(self):
        client, server = proc.waitall(self.setup_two_endpoints())
        client, server = GreenMSRPSession(client), GreenMSRPSession(server)
        client.reader_job.kill(InjectedError("Killing client's reader_job"))
        api.sleep(0.1)
        self.assertRaises(MSRPSessionError, client.send_chunk, self.make_hello(client.msrp))
        self.assertRaises(InjectedError, client.receive_chunk)
        api.sleep(0.1)
        self.assertRaises(MSRPSessionError, server.send_chunk, self.make_hello(server.msrp))
        self.assertRaises(ConnectionClosed, server.receive_chunk)

class MSRPSessionTest_TLS(TLSMixin, MSRPSessionTest):
    pass


class ServerTest(TestBase):

    server = None

    @classmethod
    def get_server(cls):
        if cls.server is None:
            cls.server = MSRPServer(logger=cls.server_logger)
        return cls.server

    def get_server_uri(self):
        return pr.URI(port=28550, use_tls=self.use_tls, credentials=self.server_credentials)

    def test_2_servers_same_port(self):
        server = self.get_server()
        server_uri_1 = server.prepare(self.get_server_uri())
        server_uri_2 = server.prepare(self.get_server_uri())
        assert len(server.ports)==1, server.ports
        assert len(server.ports.values()[0])==1, server.ports

        connector = self.get_connector()
        client1_full_local_path = connector.prepare()
        server_transport_event = TimeoutEvent()
        proc.spawn(server.complete, client1_full_local_path).link(server_transport_event)
        client1_transport = connector.complete(server_uri_1)
        server_transport = server_transport_event.wait()
        self._test_write_chunk(client1_transport, server_transport)
        self._test_write_chunk(server_transport, client1_transport)
        client1_transport.loseConnection()
        server_transport.loseConnection()

        client2_full_local_path = connector.prepare()
        server_transport_event = TimeoutEvent()
        proc.spawn(server.complete, client2_full_local_path).link(server_transport_event)
        client2_transport = connector.complete(server_uri_2)
        server_transport = server_transport_event.wait()
        self._test_write_chunk(client2_transport, server_transport)
        self._test_write_chunk(server_transport, client2_transport)
        client2_transport.loseConnection()
        server_transport.loseConnection()


class ServerTest_TLS(TLSMixin, ServerTest):
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

if options.debug:
    log.level.current = log.level.DEBUG

if options.log_client:
    TestBase.client_logger.traffic_logger = TrafficLogger.to_file(prefix='C ')
if options.log_server:
    TestBase.server_logger.traffic_logger = TrafficLogger.to_file(prefix='S ')

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

