# Copyright (C) 2008 AG Projects. See LICENSE for details 

from __future__ import with_statement
import sys

from eventlet.coros import Job, queue
from eventlet.twistedutil.protocol import GreenTransportBase
from eventlet.hubs.twistedr import callLater

from msrplib import protocol, MSRPError
from msrplib.util import random_string

# need Message-ID and Byte-Range headers in every chunk, because msrprelay fails otherwise

class MSRPTransactionError(MSRPError):
    def __init__(self, comment=None, code=None):
        if comment is not None:
            self.comment = comment
        if code is not None:
            self.code = code
        if not hasattr(self, 'code'):
            raise TypeError("must provide 'code'")

    def __str__(self):
        try:
            comment = self.comment
        except AttributeError:
            return str(self.code)
        else:
            return '%s %s' % (self.code, self.comment)

# XXX from these exception names it's unclear whether it's raised
# because of an error response from a remote party or it's a locally
# generated error (-- it's latter)

class MSRPBadRequest(MSRPTransactionError):
    code = 400
    comment = 'Bad Request'

    def __str__(self):
        return 'Remote party sent bogus data'

class MSRPBadContentType(MSRPTransactionError):
    code = 415
    comment = 'Unsupported media type'

class MSRPSessionError(MSRPTransactionError):
    code = 481
    comment = 'No such session'

data_start, data_end, write_chunk = range(3)

class Peer:

    def __init__(self, channel):
        self.channel = channel

    def data_start(self, data):
        self.channel.send((data_start, data))

    def data_end(self, continuation):
        self.channel.send((data_end, continuation))

    def write_chunk(self, contents):
        self.channel.send((write_chunk, contents))

    def connection_lost(self, reason):
        self.channel.send_exception(reason.type, reason.value, reason.tb)

class MSRPProtocol_withLogging(protocol.MSRPProtocol):

    traffic_logger = None
    _new_chunk = True

    def __init__(self, gtransport, queue): 
        self.gtransport = gtransport 
        self._queue = queue 
        protocol.MSRPProtocol.__init__(self) 

    def connectionMade(self): 
        self.gtransport.init_transport(self.transport) 
        del self.gtransport 
        self.peer = Peer(self._queue) 
        del self._queue 

    def rawDataReceived(self, data):
        if self.traffic_logger:
            self.traffic_logger.report_in(data, self.transport)
        protocol.MSRPProtocol.rawDataReceived(self, data)

    def lineReceived(self, line):
        if self.traffic_logger:
            self.traffic_logger.report_in(line+self.delimiter, self.transport, self._new_chunk)
        self._new_chunk = False
        protocol.MSRPProtocol.lineReceived(self, line)

    def connectionLost(self, reason):
       if self.peer:
           self.peer.connection_lost(reason)

    def setLineMode(self, extra):
        self._new_chunk = True
        return protocol.MSRPProtocol.setLineMode(self, extra)

def make_SEND_response(chunk, code, comment):
    """Construct a response to SEND request as described in RFC4975 Section 7.2"""
    to_path = [chunk.headers['From-Path'].decoded[0]]
    from_path = [chunk.headers['To-Path'].decoded[-1]]
    response = protocol.MSRPData(chunk.transaction_id, code=code, comment=comment)
    response.add_header(protocol.ToPathHeader(to_path))
    response.add_header(protocol.FromPathHeader(from_path))
    return response

class Message(str):
    pass

class LocalResponse(object):

    def __init__(self, code, comment):
        self.code = code
        self.comment = comment

    def __repr__(self):
        return '<LocalResponse %s %s>' % (self.code, self.comment)

Response200OK = LocalResponse(200, "OK")
Response408Timeout = LocalResponse(408, "Local transaction timed out")


class MSRPSession(GreenTransportBase):
    """An MSRP session that exclusively uses the connection.

    QQQ: there's 1-to-1 mapping between session and connection because
    msrprelay does not support otherwise.

    * Maintain list events for each unconfirmed chunks and fire them when the
      response arrives

    Does not do:
    * multiple messages
    """

    protocol_class = MSRPProtocol_withLogging
    RESPONSE_TIMEOUT = 30
    debug = True

    def __init__(self, local_uri, traffic_logger=None, allowed_content_types=None, debug=None):
        if not isinstance(local_uri, protocol.URI):
            raise TypeError('Not MSRP URI instance: %r' % local_uri)
        # The following members define To-Path and From-Path headers as following:
        # * Outgoing request:
        #   From-Path: local_uri
        #   To-Path: local_path + remote_path + [remote_uri]
        # * Incoming request:
        #   From-Path: remote_path + remote_uri
        #   To-Path: remote_path + local_path + [local_uri] # XXX
        self.local_uri = local_uri
        self.local_path = []
        self.remote_uri = None
        self.remote_path = []
        self.traffic_logger = traffic_logger
        self.allowed_content_types = allowed_content_types
        if debug is not None:
            self.debug = debug
        self.expected_responses = {}
        self.reader_job = None
        self.incoming = queue(1)
        #self.chunks = {} # maps message_id to StringIO instance that represents contents of the message

    def next_host(self):
        if self.local_path:
            return self.local_path[0]
        return self.full_remote_path[0]

    def use_path(self, lst):
        self.local_path = lst

    @property
    def full_local_path(self):
        "suitable to put into INVITE"
        return self.local_path + [self.local_uri]

    @property
    def full_remote_path(self):
        return self.remote_path + [self.remote_uri]

    def make_chunk(self, transaction_id=None, method='SEND', code=None, comment=None, data='', contflag='$'):
        """Make a new MSRPData object with From and To headers set up"""
        if transaction_id is None:
            transaction_id=random_string(12)
        chunk = protocol.MSRPData(transaction_id=transaction_id, method=method, code=code, comment=comment)
        chunk.add_header(protocol.ToPathHeader(self.local_path + self.remote_path + [self.remote_uri]))
        chunk.add_header(protocol.FromPathHeader([self.local_uri]))
        # Byte-Range and Message-ID are neccessary because otherwise msrprelay does not work
        chunk.add_header(protocol.ByteRangeHeader((1, len(data), len(data))))
        chunk.add_header(protocol.MessageIDHeader(str(random_string(10))))
        chunk.data = data
        chunk.contflag = contflag
        return chunk

    def build_protocol(self):
        p = GreenTransportBase.build_protocol(self)
        p.traffic_logger = self.traffic_logger
        return p

    def write(self, data):
        if self.traffic_logger:
            self.traffic_logger.report_out(data, self.transport)
        return self.transport.write(data)

    def write_chunk(self, chunk):
        """Encode chunk and write it to the underlying transport"""
        self.write(chunk.encode())

    def write_SEND_response(self, chunk, code, comment):
        assert chunk.method=='SEND', repr(chunk)
        if chunk.failure_report=='no':
            return
        if chunk.failure_report=='partial' and code==200:
            return
        try:
            response = make_SEND_response(chunk, code, comment)
        except Exception:
            # there could an exception if chunk is somehow broken
            if self.debug:
                raise
        else:
            return self.write_chunk(response)

    def _wait_chunk(self):
        """Wait for a new chunk. Return it bypassing self.incoming"""
        data = ''
        func, msrpdata = self._wait()
        if func!=data_start:
            raise MSRPBadRequest
        func, param = self._wait()
        while func==write_chunk:
            data += param
            func, param = self._wait()
        if func!=data_end:
            raise MSRPBadRequest
        if param not in "$+#":
            raise MSRPBadRequest
        msrpdata.data = data
        msrpdata.contflag = param
        return msrpdata

    def _wait_chunk_respond_errors(self, raise_on_error=False):
        """Wait for a new chunk. Return it bypassing self.incoming.

        Send the following responses in appropriate situations:
        * 400 Bad Request
        * 481 No Such Session Here
        Then continue receiving if raise_on_error is False, otherwise an exception is raised.
        """
        while True:
            try:
                chunk = self._wait_chunk()
            except MSRPBadRequest, error:
                if chunk.method == 'SEND':
                    # QQQ may send this more than once in a row for the same transaction
                    # QQQ chunk is incomplete here, may have no to-path/from-path headers
                    self.write_SEND_response(chunk, error.code, error.comment)
                    if raise_on_error:
                        raise
            else:
                # QQQ do I need to check that To-Path and From-Path
                # present or is it handled by msrp_protocol
                if chunk.method=='SEND':
                    error = self.check_path_headers_SEND(chunk)
                    if error is not None:
                        self.write_SEND_response(chunk, error.code, error.comment)
                        if raise_on_error:
                            raise error
                        else:
                            continue
                return chunk

    def _reader(self, raise_on_error=False):
        """Wait forever for new chunks.

        Send the good ones to self.incoming queue.
        Pop and notify an event in self.expected_responses
        when transaction response is received.
        """
        try:
            while True:
                chunk = self._wait_chunk_respond_errors(raise_on_error=raise_on_error)
                if chunk.method is None: # response
                    try:
                        event, timer = self.expected_responses.pop(chunk.transaction_id)
                    except KeyError:
                        continue
                    else:
                        if timer is not None:
                            timer.cancel()
                        event.send(chunk)
                elif chunk.method=='SEND':
                    error = self.check_content_type(chunk)
                    if error is not None:
                        self.write_SEND_response(chunk, error.code, error.comment)
                        if raise_on_error:
                            raise
                    else:
                        self.write_SEND_response(chunk, 200, "OK")
                        self.incoming.send(chunk)
                elif chunk.method=='REPORT':
                    pass
                else:
                    pass # respond 506
        except:
            self.incoming.send_exception(*sys.exc_info())
            raise

    def receive_chunk(self):
        if self.reader_job:
            return self.incoming.wait()
        else:
            self.reader_job.poll() # re-raise the exception that killed reader

    def send_chunk(self, chunk, event=None):
        """Send `chunk'. Report the result via `event'.

        When `event' argument is present, it will be used to report
        the response to the caller. When a real response is received,
        `event' is fired with MSRPData object. When the response is
        generated locally it's a LocalResponse instance.

        If no response was received after RESPONSE_TIMEOUT seconds,
        * 408 response is generated if Failure-Report was 'yes' or absent
        * 200 response is generated if Failure-Report was 'partial' or 'no'
        
        Note that it's rather wasteful to provide `event' argument other than None
        for chunks with Failure-Report='no' since it will always fire 30 seconds later
        with 200 result (unless the other party is broken and ignores Failure-Report header)
        """
        self.reader_job.poll() # re-raise the exception that killed reader
        id = chunk.transaction_id
        assert id not in self.expected_responses, "MSRP transaction %r is already in progress" % id
        if event is not None:
            # since reader is in another greenlet and write_chunk may block,
            # let's setup ResponseEventTimer before write_chunk() call, just in case
            event_timer = [event, None]
            self.expected_responses[id] = event_timer
        try:
            self.write_chunk(chunk)
            # must start timer after data was submitted to the OS. However, twisted's transport
            # introduces additional buffer. I cannot just disable it (by setting bufferSize to 1)
            # because bufferSize applies both to write buffering and recv's argument (why?)
            # need to hack twisted.internet.tcp.
        except:
            if event is not None and id in self.expected_responses:
                del self.expected_responses[id]
            raise
        else:
            if event is not None:
                timeout_error = Response408Timeout if chunk.failure_report=='yes' else Response200OK
                from twisted.internet import reactor
                timer = callLater(reactor, self.RESPONSE_TIMEOUT, self._response_timeout, id, timeout_error)
                event_timer[1] = timer

    def _response_timeout(self, id, timeout_error):
        try:
            event, timer = self.expected_responses.pop(id)
        except KeyError:
            pass
        else:
            if timer is not None:
                timer.cancel()
            event.send(timeout_error)

    def check_path_headers_SEND(self, chunk):
        assert chunk.method=='SEND', repr(chunk)
        ToPath = list(chunk.headers['To-Path'].decoded)
        FromPath = list(chunk.headers['From-Path'].decoded)
        ExpectedTo = [self.local_uri]
        ExpectedFrom = self.local_path + self.remote_path + [self.remote_uri]
        if ToPath!=ExpectedTo or FromPath!=ExpectedFrom:
            return MSRPSessionError('To-Path: expected %r, got %r' % (ExpectedTo, ToPath))
        if FromPath != ExpectedFrom:
            return MSRPSessionError('From-Path: expected %r, got %r' % (ExpectedFrom, FromPath))

    def check_content_type(self, chunk):
        if chunk.headers.get('Content-Type') is None:
            return MSRPBadContentType('Content-type header missing')
        if self.allowed_content_types is not None:
            if chunk.headers['Content-Type'].decoded not in self.allowed_content_types:
                return MSRPBadContentType

    def _set_full_remote_path(self, full_remote_path):
        "as received in response to INVITE"
        if not all(isinstance(x, protocol.URI) for x in full_remote_path):
            raise TypeError('Not all elements are MSRP URI: %r' % full_remote_path)
        self.remote_uri = full_remote_path[-1]
        self.remote_path = full_remote_path[:-1]

    def bind(self, full_remote_path):
        self._set_full_remote_path(full_remote_path)
        chunk = self.make_chunk()
        self.write_chunk(chunk)
        response = self._wait_chunk()
        if response.code != 200:
            raise MSRPSessionError('Cannot bind session: %s' % response)
        self.reader_job = Job.spawn_new(self._reader, self.debug)

    def accept_binding(self, full_remote_path):
        self._set_full_remote_path(full_remote_path)
        chunk = self._wait_chunk_respond_errors(raise_on_error=True)
        self.write_SEND_response(chunk, 200, "OK")
        if 'Content-Type' in chunk.headers or len(chunk.data)>0:
            self.incoming.send(chunk)
        self.reader_job = Job.spawn_new(self._reader, self.debug)

    def make_message(self, msg, content_type):
        chunk = self.make_chunk(data=msg)
        chunk.add_header(protocol.ContentTypeHeader(content_type))
        return chunk

    def send_message(self, msg, content_type):
        chunk = self.make_message(msg, content_type)
        self.send_chunk(chunk)
        return chunk

