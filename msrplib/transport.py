# Copyright (C) 2008 AG Projects. See LICENSE for details

from __future__ import with_statement
import sys
from twisted.internet.error import ConnectionClosed

from gnutls.errors import GNUTLSError

from eventlet import api, coros, proc
from eventlet.twistedutil.protocol import GreenTransportBase, ValueQueue

from msrplib import protocol, MSRPError
from msrplib.util import random_string

# need Message-ID and Byte-Range headers in every chunk, because msrprelay fails otherwise

ConnectionClosedErrors = (ConnectionClosed, GNUTLSError)

class MSRPTransactionError(MSRPError):
    def __init__(self, comment=None, code=None):
        if comment is not None:
            self.comment = comment
        if code is not None:
            self.code = code
        if not hasattr(self, 'code'):
            raise TypeError("must provide 'code'")

    def __str__(self):
        if hasattr(self, 'comment'):
            return '%s %s' % (self.code, self.comment)
        else:
            return str(self.code)

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


class MSRPProtocol_withLogging(protocol.MSRPProtocol):

    traffic_logger = None
    state_logger = None
    _new_chunk = False

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
        if self.state_logger:
            self.state_logger.report_disconnected(self.transport, reason)
        protocol.MSRPProtocol.connectionLost(self, reason)
    # QQQ logging for readConnectionLost / writeConnectionLost ?

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


class LocalResponse(object):

    def __init__(self, code, comment):
        self.code = code
        self.comment = comment

    def __repr__(self):
        return '<LocalResponse %s %s>' % (self.code, self.comment)

Response200OK = LocalResponse(200, "OK")
Response408Timeout = LocalResponse(408, "Local transaction timed out")
# XXX LocalResponse has the same attributes as MSRPTransactionError


class MSRPTransport(GreenTransportBase):
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
    _got_data = None
    SHUTDOWN_TIMEOUT = 1

    def __init__(self, local_uri, traffic_logger=None, state_logger=None,
                 allowed_content_types=None, debug=None, incoming=None):
        GreenTransportBase.__init__(self)
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
        self.state_logger = state_logger
        self.allowed_content_types = allowed_content_types
        if debug is not None:
            self.debug = debug
        self.expected_responses = {}
        self.reader_job = None
        if incoming is None:
            incoming = ValueQueue()
        self.incoming = incoming
        self.outgoing = coros.queue()
        self.writer_job = None
        #self.chunks = {} # maps message_id to StringIO instance that represents contents of the message
        self._disconnecting = False

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
        chunk.add_header(protocol.MessageIDHeader(random_string(10)))
        chunk.data = data
        chunk.contflag = contflag
        return chunk

    def build_protocol(self):
        p = GreenTransportBase.build_protocol(self)
        p.traffic_logger = self.traffic_logger
        p.state_logger = self.state_logger
        return p

    def _data_start(self, data):
        self._queue.send((data_start, data))

    def _data_end(self, continuation):
        self._queue.send((data_end, continuation))

    def _write_chunk(self, contents):
        self._queue.send((write_chunk, contents))

    def initiate_shutdown(self):
        # XXX break the current chunk
        self._disconnecting = True
        self.outgoing.send(None)

    def shutdown(self):
        """Shutdown the connection.

        1) Finish sending outgoing queue.
        2) Lose write connection.
        3) Wait for the other party to finish sending
        4) If the other party won't finish in SHUTDOWN_TIMEOUT seconds, close
           the connection
        """
        try:
            self.initiate_shutdown()
            self.writer_job.wait(None, None)
            self.reader_job.wait(self.SHUTDOWN_TIMEOUT, None)
        finally:
            self.loseConnection()

    def write(self, data):
        if self.traffic_logger:
            self.traffic_logger.report_out(data, self.transport)
        return GreenTransportBase.write(self, data)

    def write_chunk(self, chunk):
        """Encode chunk and write it to the underlying transport"""
        self.write(chunk.encode())

    def make_SEND_response(self, chunk, code, comment):
        assert chunk.method=='SEND', repr(chunk)
        if chunk.failure_report=='no':
            return
        if chunk.failure_report=='partial' and code==200:
            return
        try:
            return make_SEND_response(chunk, code, comment)
        except Exception:
            # there could an exception if chunk is somehow broken
            if self.debug:
                raise

    def write_SEND_response(self, chunk, code, comment):
        response = self.make_SEND_response(chunk, code, comment)
        self.write_chunk(response)
        return response

    def send_SEND_response(self, chunk, code, comment):
        response = self.make_SEND_response(chunk, code, comment)
        self.send_chunk(response)
        return response

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

    # XXX deprecate raise_on_error. instead log information about bad chunk and close the connection
    def _wait_chunk_respond_errors(self, raise_on_error=False):
        """Wait for a new chunk. Return it bypassing self.incoming.

        Send the following responses in appropriate situations:
        * 400 Bad Request
        * 481 No Such Session Here
        then continue receiving if raise_on_error is False, otherwise an exception is raised.
        """
        while True:
            try:
                chunk = self._wait_chunk()
            except MSRPBadRequest, error:
                if chunk.method == 'SEND':
                    # QQQ may send this more than once in a row for the same transaction
                    # QQQ chunk is incomplete here, may have no to-path/from-path headers
                    self.send_SEND_response(chunk, error.code, error.comment)
                    if raise_on_error:
                        raise
            else:
                # QQQ do I need to check that To-Path and From-Path
                # present or is it handled by msrp_protocol
                if chunk.method=='SEND':
                    error = self.check_path_headers_SEND(chunk)
                    if error is not None:
                        self.send_SEND_response(chunk, error.code, error.comment)
                        if raise_on_error:
                            raise error
                        else:
                            continue
                return chunk

    def _reader(self, raise_on_error=False):
        """Wait forever for new chunks. Send the good ones to self.incoming queue.

        If a response to a previously sent chunk is received, pop the corresponding
        event from self.expected_responses and send the response there.
        """
        self.state_logger.dbg('reader: started')
        try:
            while not self._disconnecting:
                chunk = self._wait_chunk_respond_errors(raise_on_error=raise_on_error)
                self.state_logger.dbg('reader: got chunk %r' % chunk)
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
                        self.send_SEND_response(chunk, error.code, error.comment)
                        if raise_on_error:
                            raise
                    else:
                        try:
                            self.send_SEND_response(chunk, 200, "OK")
                        finally:
                            self.state_logger.dbg('reader: sending %r to incoming' % chunk)
                            self.incoming.send(chunk)
                elif chunk.method=='REPORT':
                    # QQQ deliver to incoming as well
                    pass
                else:
                    pass # QQQ respond 506
        except ConnectionClosedErrors, ex:
            self.state_logger.dbg('reader: exiting because of %r' % ex)
            self.incoming.send_exception(ex)
        except:
            self.state_logger.dbg('reader: losing connection because of %r' % (sys.exc_info(), ))
            self.unregisterProducer()
            self.transport.loseConnection()
            self.incoming.send_exception(*sys.exc_info())
            raise
        finally:
            self.initiate_shutdown()
            if not self.writer_job:
                self.state_logger.dbg('reader: losing connection because writer has finished already')
                self.unregisterProducer()
                self.transport.loseConnection()

    def receive_chunk(self):
        return self.incoming.wait()

    def _writer(self):
        self.state_logger.dbg('writer: started')
        try:
            while not self._disconnecting:
                send_params = self.outgoing.wait()
                if send_params is None:
                    # user has called shutdown
                    # XXX what about rest of outgoing
                    self.state_logger.dbg('writer: shutdown() was called')
                    break
                self.state_logger.dbg('writer: processing %s' % (send_params, ))
                self._send_chunk(*send_params)
                self.state_logger.dbg('writer: sent chunk %s' % (send_params, ))
            while self.outgoing:
                send_params = self.outgoing.wait()
                if send_params is not None:
                    self.state_logger.dbg('writer: processing %s' % (send_params, ))
                    self._send_chunk(*send_params)
                    self.state_logger.dbg('writer: sent chunk %s' % (send_params, ))
        except ConnectionClosedErrors, ex:
            self.state_logger.dbg('writer: exiting because of %r' % (ex, ))
            # the error will be available via self._write_disconnected_event
        except:
            self.state_logger.dbg('writer: losing connection because of %r' % (sys.exc_info(), ))
            self.transport.loseConnection()
            raise
        finally:
            self.transport.unregisterProducer()
            if self.reader_job:
                self.state_logger.dbg('writer: lose write connection')
                self.transport.loseWriteConnection()
            else:
                self.state_logger.dbg('writer: lose connection because reader has finished already')
                self.transport.loseConnection()

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
        if self._write_disconnected_event.ready(): # rename to self._lost_write_event
            raise self._write_disconnected_event.wait()
        if chunk.method == 'SEND' and (chunk.failure_report, chunk.success_report) != ('no', 'no'):
            if self._read_disconnected_event.ready():
                raise self._read_disconnected_event.wait()
            assert not self.reader_job.dead, self.reader_job
        assert not self.writer_job.dead, self.writer_job
        self.outgoing.send((chunk, event))

    def _send_chunk(self, chunk, event=None):
        id = chunk.transaction_id
        assert id not in self.expected_responses, "MSRP transaction %r is already in progress" % id
        if event is not None:
            # since reader is in another greenlet and write_chunk will switch() the greenlets,
            # let's setup response's event and timer before write_chunk() call, just in case
            event_and_timer = [event, None]
            self.expected_responses[id] = event_and_timer
        try:
            self.write_chunk(chunk)
        except:
            if event is not None:
                self.expected_responses.pop(id, None)
            raise
        else:
            if event is not None:
                timeout_error = Response408Timeout if chunk.failure_report=='yes' else Response200OK
                timer = api.get_hub().schedule_call_global(self.RESPONSE_TIMEOUT, self._response_timeout, id, timeout_error)
                event_and_timer[1] = timer

    def _response_timeout(self, id, timeout_error):
        event, timer = self.expected_responses.pop(id, (None, None))
        if event is not None:
            event.send(timeout_error)
            if timer is not None:
                timer.cancel()

    def deliver_chunk(self, chunk, event=None):
        """Send chunk, return the transaction response.
        Return None immediatelly if chunk's Failure-Report is 'no'.
        """
        if chunk.failure_report!='no' and event is None:
            event = coros.event()
        self.send_chunk(chunk, event)
        if event is not None:
            return event.wait()

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
        self.reader_job = proc.spawn(self._reader, self.debug)
        self.writer_job = proc.spawn(self._writer)

    def accept_binding(self, full_remote_path):
        self._set_full_remote_path(full_remote_path)
        chunk = self._wait_chunk_respond_errors(raise_on_error=True)
        self.write_SEND_response(chunk, 200, "OK")
        if 'Content-Type' in chunk.headers or len(chunk.data)>0:
            self.incoming.send(chunk)
        self.reader_job = proc.spawn(self._reader, self.debug)
        self.writer_job = proc.spawn(self._writer)

    def make_message(self, msg, content_type):
        chunk = self.make_chunk(data=msg)
        chunk.add_header(protocol.ContentTypeHeader(content_type))
        return chunk

    def send_message(self, msg, content_type):
        chunk = self.make_message(msg, content_type)
        self.send_chunk(chunk)
        return chunk

    def deliver_message(self, msg, content_type):
        chunk = self.make_message(msg, content_type)
        self.deliver_chunk(chunk)
        return chunk

