from __future__ import with_statement
import sys
import unittest
import new

from twisted.internet.error import ConnectionDone
from twisted.names.srvconnect import SRVConnector
from twisted.internet import reactor

from eventlet.api import timeout, exc_after, TimeoutError
from eventlet.coros import event, JobGroup

# this will print stacktraces in all greenlets that had an error
#from eventlet import coros
#coros.DEBUG = True

from msrplib.connect import MSRPConnectFactory, MSRPAcceptFactory, MSRPRelaySettings, ConnectBase
from msrplib import protocol as pr
from msrplib.trafficlog import TrafficLogger, hook_std_output, HeaderLogger_File
from msrplib.transport import MSRPSession

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
        with timeout(self.timeout):
            return event.wait(self)

def _connect_msrp(local_event, remote_event, msrp, local_uri):
    full_local_path = msrp.prepare(local_uri)
    try:
        local_event.send(full_local_path)
        full_remote_path = remote_event.wait()
        result = msrp.complete(full_remote_path)
        assert isinstance(result, MSRPSession), repr(result)
        return result
    finally:
        msrp.cleanup()

class MSRPSession_ZeroTimeout(MSRPSession):
    RESPONSE_TIMEOUT = 0

class MSRPSession_NoResponse(MSRPSession):
    count = 0
    def write_SEND_response(self, chunk, code, comment):
        if not self.count:
            self.count += 1
            MSRPSession.write_SEND_response(self, chunk, code, comment)

class BasicTest(unittest.TestCase):
    server_relay = None
    client_relay = None
    client_traffic_logger = None # TrafficLogger(HeaderLogger_File(prefix='C '))
    server_traffic_logger = None # TrafficLogger(HeaderLogger_File(prefix='S '))
    PER_TEST_TIMEOUT = 30
    RESPONSE_TIMEOUT = 10
    debug = True

    def setup_two_endpoints(self, clientMSRPSession=MSRPSession, serverMSRPSession=MSRPSession):
        server_path = TimeoutEvent()
        client_path = TimeoutEvent()

        def client():
            msrp = MSRPConnectFactory.new(self.client_relay, self.client_traffic_logger,
                                          MSRPSessionClass=clientMSRPSession)
            return _connect_msrp(client_path, server_path, msrp)

        def server():
            msrp = MSRPAcceptFactory.new(self.server_relay, self.server_traffic_logger,
                                         MSRPSessionClass=serverMSRPSession)
            return _connect_msrp(server_path, client_path, msrp)

        group = JobGroup()
        group.client = group.spawn_new(client)
        group.server = group.spawn_new(server)
        return group

    def setUp(self):
        self.timer = exc_after(self.PER_TEST_TIMEOUT, TimeoutError('per test timeout expired'))

    def tearDown(self):
        self.timer.cancel()
        del self.timer

    def assertHeaderEqual(self, header, chunk1, chunk2):
        self.assertEqual(chunk1.headers[header].decoded, chunk2.headers[header].decoded)

    def assertSameData(self, chunk1, chunk2):
        self.assertHeaderEqual('Content-Type', chunk1, chunk2)
        self.assertEqual(chunk1.data, chunk2.data)
        self.assertEqual(chunk1.contflag, chunk2.contflag)

    def deliver_chunk(self, msrp, chunk):
        e = event()
        msrp.send_chunk(chunk, e)
        with timeout(self.RESPONSE_TIMEOUT, TimeoutError('Did not received transaction response')):
            response = e.wait()
        return response

# instead of the following, hook logger interface and check that there's no data on the wire
#     def assertNoIncoming(self, seconds, *connections):
#         for connection in connections:
#             with timeout(seconds, None):
#                 res = connection.receive_chunk()
#                 raise AssertionError('received %r' % res)
#         for connection in connections:
#             assert not connection.incoming, connection.incoming
#             assert connection.reader_job.poll() is None
#             assert connection.connected
#
    def _make_hello(self, msrp):
        x = msrp.make_chunk(data='hello')
        x.add_header(pr.ContentTypeHeader('text/plain'))
        return x

    def _send_chunk(self, sender, receiver):
        x = self._make_hello(sender)
        response = self.deliver_chunk(sender, x)
        assert response.code == 200, response
        y = receiver.receive_chunk()
        self.assertSameData(x, y)

    def test_send_chunk(self):
        jobs = self.setup_two_endpoints()
        client, server = jobs.wait_all()
        #client = client.wait()
        #server = server.wait()
        self._send_chunk(client, server)
        self._send_chunk(server, client)
        #self.assertNoIncoming(0.1, client, server)

    def test_send_chunk_response_localtimeout(self):
        client, server = self.setup_two_endpoints(clientMSRPSession=MSRPSession_ZeroTimeout).wait_all()
        x = self._make_hello(client)
        response = self.deliver_chunk(client, x)
        assert response.code == 408, response
        y = server.receive_chunk()
        self.assertSameData(x, y)
        #self.assertNoIncoming(0.1, client, server)

    def _test_closed(self, wait_func, *args, **kwargs):
        try:
            msg = "%s didn't raise ConnectionDone within %s seconds" % (wait_func, self.RESPONSE_TIMEOUT)
            with timeout(self.RESPONSE_TIMEOUT, TimeoutError(msg)):
                result = wait_func(*args, **kwargs)
        except ConnectionDone:
            pass
        else:
            raise AssertionError('%s must raise ConnectionDone, returned %r' % (wait_func, result))

    def test_close_connection__receive(self):
        client, server = self.setup_two_endpoints().wait_all()
        assert isinstance(client, MSRPSession), repr(client)
        client.loseConnection()
        self._test_closed(server.receive_chunk)
        self._test_closed(server.send_chunk, self._make_hello(server))


from optparse import OptionParser
parser = OptionParser()
parser.add_option('--domain')
parser.add_option('--username')
parser.add_option('--password')
parser.add_option('--host')
parser.add_option('--port', default=2855)
options, _args = parser.parse_args()

relays = []
# SRV:
if options.domain is not None:
    relays.append(MSRPRelaySettings(options.domain, options.username, options.password))
# explicit host:
if options.host is not None:
    assert options.domain is not None
    relays.append(MSRPRelaySettings(options.domain, options.username, options.password, options.host, options.port))

print relays

configs = []
for relay in relays:
    configs.append({'server_relay': relay, 'client_relay': None})
    configs.append({'server_relay': relay, 'client_relay': relay})

def get_config_name(config):
    return '_'.join(k for (k, v) in config.items() if v is not None)

def make_tests_for_other_configurations(TestClass):
    klass = TestClass.__name__
    for config in configs:
        config_name = get_config_name(config)
        klass_name = klass + '_' + config_name
        while klass_name in globals():
            klass_name += '_x'
        new_class = new.classobj(klass_name, (TestClass, ), config)
        print klass_name
        globals()[klass_name] = new_class

make_tests_for_other_configurations(BasicTest)

if __name__=='__main__':
    test = unittest.defaultTestLoader.loadTestsFromModule(sys.modules['__main__'])
    testRunner = unittest.TextTestRunner().run(test)

