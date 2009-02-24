# Copyright (C) 2008 AG Projects. See LICENSE for details

from __future__ import with_statement
import sys
import random
from copy import copy
from time import time
from application import log
from twisted.internet.error import ConnectionClosed, ConnectionDone
from gnutls.errors import GNUTLSError
from eventlet import api, coros, proc
from eventlet.twistedutil.protocol import GreenTransportBase, ValueQueue

from msrplib import protocol, MSRPError

# need Message-ID and Byte-Range headers in every chunk, because msrprelay fails otherwise

ConnectionClosedErrors = (ConnectionClosed, GNUTLSError)

class ChunkParseError(MSRPError):
    """Failed to parse incoming chunk"""

class MSRPSessionError(MSRPError):
    pass

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

class MSRPNoSuchSessionError(MSRPTransactionError):
    code = 481
    comment = 'No such session'

data_start, data_end, data_write, data_final_write = xrange(4)


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

    def setLineMode(self, extra):
        self._new_chunk = True
        return protocol.MSRPProtocol.setLineMode(self, extra)


def make_response(chunk, code, comment):
    """Construct a response to a request as described in RFC4975 Section 7.2.
    If the response is not needed, return None.
    If a required header missing, raise ChunkParseError.
    """
    if chunk.failure_report=='no':
        return
    if chunk.failure_report=='partial' and code==200:
        return
    if not chunk.headers.get('To-Path'):
        raise ChunkParseError('missing To-Path header: %r' % chunk)
    if not chunk.headers.get('From-Path'):
        raise ChunkParseError('missing From-Path header: %r' % chunk)
    to_path = [chunk.headers['From-Path'].decoded[0]]
    if chunk.method=='SEND':
        from_path = [chunk.headers['To-Path'].decoded[-1]]
    else:
        from_path = chunk.headers['To-Path'].decoded
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
    protocol_class = MSRPProtocol_withLogging

    def __init__(self, local_uri, traffic_logger=None, state_logger=None):
        GreenTransportBase.__init__(self)
        if not isinstance(local_uri, protocol.URI):
            raise TypeError('Not MSRP URI instance: %r' % (local_uri, ))
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
        self._msrpdata = None

    def next_host(self):
        if self.local_path:
            return self.local_path[0]
        return self.full_remote_path[0]

    def set_local_path(self, lst):
        self.local_path = lst

    @property
    def full_local_path(self):
        "suitable to put into INVITE"
        return self.local_path + [self.local_uri]

    @property
    def full_remote_path(self):
        return self.remote_path + [self.remote_uri]

    def make_chunk(self, transaction_id=None, method='SEND', code=None, comment=None, data='',
                   contflag=None, start=1, end=None, length=None):
        """Make a new MSRPData object with From and To headers set up"""
        if transaction_id is None:
            transaction_id = '%x' % random.getrandbits(64)
        chunk = protocol.MSRPData(transaction_id=transaction_id, method=method, code=code, comment=comment)
        chunk.add_header(protocol.ToPathHeader(self.local_path + self.remote_path + [self.remote_uri]))
        chunk.add_header(protocol.FromPathHeader([self.local_uri]))
        if end is None:
            end = start - 1 + len(data)
        if length is None:
            length = start - 1 + len(data)
        if contflag is None:
            if end == length:
                contflag = '$'
            else:
                contflag = '+'
        chunk.add_header(protocol.ByteRangeHeader((start, end, length)))
        chunk.add_header(protocol.MessageIDHeader('%x' % random.getrandbits(64)))
        # Byte-Range and Message-ID are neccessary because otherwise msrprelay does not work
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

    def _data_write(self, contents, final):
        if final:
            self._queue.send((data_write, contents))
        else:
            self._queue.send((data_final_write, contents))

    def write(self, data):
        if self.traffic_logger:
            self.traffic_logger.report_out(data, self.transport)
        return GreenTransportBase.write(self, data)

    def read_chunk(self, size=None):
        """Wait for a new chunk and return it.
        If there was an error, lose Connection and raise ChunkParseError

        In case of unintelligible input, lose the connection and return None.
        When connection is closed, raise the reason of the closure (e.g. ConnectionDone).

        If the data already read exceeds `size', stop reading the data and return
        a "virtual" chunk, i.e. the one that does not actually correspond the the real
        MSRP chunk. Such chunks have Byte-Range header fixed and continuation that is '+';
        they also posses 'segment' attribute, an integer, starting with 1 and increasing
        with every new segment of the chunk.

        Note, that `size' only hints when to interrupt the segment but does not affect
        how the data is read from socket. You may have segments bigger than `size' and it's
        legal to set `size' to zero (which would mean return a chunk as long as you get
        some data, regardless how small)
        """
        data = ''
        if self._msrpdata is None:
            func, msrpdata = self._wait()
            if func!=data_start:
                self.state_logger.write('Bad data: %r %r' % (func, msrpdata))
                self.loseConnection()
                raise ChunkParseError
        else:
            msrpdata = self._msrpdata
        func, param = self._wait()
        while func==data_write:
            data += param
            if size is not None and len(data)>=size:
                if msrpdata.segment is None:
                    msrpdata.segment = 1
                else:
                    msrpdata.segment += 1
                self._msrpdata = copy(msrpdata)
                msrpdata.data = data
                msrpdata.contflag = '+'
                msrpdata.final = False
                return msrpdata
            func, param = self._wait()
        if func == data_final_write:
            data += param
            func, param = self._wait()
        if func != data_end:
            self.state_logger.write('Bad data: %r %r' % (func, param))
            self.loseConnection()
            raise ChunkParseError
        if param not in "$+#":
            self.state_logger.write('Bad data: %r %r' % (func, param))
            self.loseConnection()
            raise ChunkParseError
        msrpdata.data = data
        msrpdata.contflag = param
        self._msrpdata = None
        self.state_logger.dbg('read_chunk -> %r' % (msrpdata, ))
        return msrpdata

    def _set_full_remote_path(self, full_remote_path):
        "as received in response to INVITE"
        if not all(isinstance(x, protocol.URI) for x in full_remote_path):
            raise TypeError('Not all elements are MSRP URI: %r' % full_remote_path)
        self.remote_uri = full_remote_path[-1]
        self.remote_path = full_remote_path[:-1]

    def bind(self, full_remote_path):
        self._set_full_remote_path(full_remote_path)
        chunk = self.make_chunk()
        self.write(chunk.encode())
        response = self.read_chunk()
        if response.code != 200:
            self.loseConnection()
            raise MSRPNoSuchSessionError('Cannot bind session: %s' % response)

    def write_response(self, chunk, code, comment):
        """Generate and write the response, lose the connection in case of error"""
        try:
            response = make_response(chunk, code, comment)
        except ChunkParseError, ex:
            log.error('Failed to generate a response: %s' % ex)
            self.loseConnection(blocking=False)
            raise
        except Exception:
            log.error('Failed to generate a response')
            log.err()
            self.loseConnection(blocking=False)
            raise
        else:
            if response is not None:
                self.write(response.encode())

    def accept_binding(self, full_remote_path):
        self._set_full_remote_path(full_remote_path)
        chunk = self.read_chunk()
        error = self.check_incoming_SEND_chunk(chunk)
        if error is None:
            code, comment = 200, 'OK'
        else:
            code, comment = error.code, error.comment
        self.write_response(chunk, code, comment)
        if 'Content-Type' in chunk.headers or len(chunk.data)>0:
            # deliver chunk to read_chunk
            raise NotImplementedError

    def check_incoming_SEND_chunk(self, chunk):
        assert chunk.method=='SEND', repr(chunk)
        try:
            ToPath = chunk.headers['To-Path']
        except KeyError:
            return MSRPBadRequest('To-Path header missing')
        try:
            FromPath = chunk.headers['From-Path']
        except KeyError:
            return MSRPBadRequest('From-Path header missing')
        ToPath = list(ToPath.decoded)
        FromPath = list(FromPath.decoded)
        ExpectedTo = [self.local_uri]
        ExpectedFrom = self.local_path + self.remote_path + [self.remote_uri]
        if ToPath!=ExpectedTo or FromPath!=ExpectedFrom:
            log.error('To-Path: expected %r, got %r' % (ExpectedTo, ToPath))
            return MSRPNoSuchSessionError('Invalid To-Path')
        if FromPath != ExpectedFrom:
            log.error('From-Path: expected %r, got %r' % (ExpectedFrom, FromPath))
            return MSRPNoSuchSessionError('Invalid From-Path')


class MSRPSession(object):
    # if incoming chunk is bigger than this, split it (for the reporting purposes)
    INCOMING_CHUNK_SIZE = 1024*16

    RESPONSE_TIMEOUT = 30
    SHUTDOWN_TIMEOUT = 1

    def __init__(self, msrptransport, allowed_content_types=None):
        self.msrp = msrptransport
        self.state_logger = self.msrp.state_logger
        self.allowed_content_types = allowed_content_types
        self.expected_responses = {}
        #self.expected_success_reports = {}
        self.outgoing = coros.queue()
        self.reader_job = proc.spawn(self._reader)
        self.writer_job = proc.spawn(self._writer)
        self.state = 'CONNECTED' # -> 'FLUSHING' -> 'CLOSING' -> 'DONE'
        # in FLUSHING writer sends only while there's something in the outgoing queue
        # then it exits and sets state to 'CLOSING' which makes reader only pay attention
        # to responses and success reports. (XXX it can now discard incoming data chunks
        # with direct write() since writer is dead)
        self.reader_job.link(self.writer_job)
        self.incoming = ValueQueue()
        self.last_expected_response = 0

    def set_state(self, state):
        self.state_logger.dbg('%s (was %s)' % (state, self.state))
        self.state = state

    @property
    def connected(self):
        return self.state=='CONNECTED'

    def shutdown(self, sync=True):
        self.set_state('FLUSHING')
        self.outgoing.send(None)
        if sync:
            self.writer_job.wait(None, None)
            self.reader_job.wait(None, None)

    def _handle_incoming_response(self, chunk):
        try:
            event, timer = self.expected_responses.pop(chunk.transaction_id)
        except KeyError:
            pass
        else:
            if timer is not None:
                timer.cancel()
            event.send(chunk)

    def _check_incoming_SEND(self, chunk):
        if chunk.method=='SEND' and chunk.segment is None:
            error = self.msrp.check_incoming_SEND_chunk(chunk)
            if error is not None:
                return error
            if chunk.headers.get('Content-Type') is None:
                return MSRPBadContentType('Content-type header missing')
            if self.allowed_content_types is not None:
                if chunk.headers['Content-Type'].decoded not in self.allowed_content_types:
                    return MSRPBadContentType

    def _handle_incoming_SEND(self, chunk):
        error = self._check_incoming_SEND(chunk)
        if error is None:
            code, comment = 200, 'OK'
        else:
            code, comment = error.code, error.comment
        if chunk.final:
            response = make_response(chunk, code, comment)
            if response is not None:
                self.outgoing.send((response, None))
        if code==200:
            self.incoming.send(chunk)

    def _reader(self):
        """Wait forever for new chunks. Send the good ones to self.incoming queue.

        If a response to a previously sent chunk is received, pop the corresponding
        event from self.expected_responses and send the response there.
        """
        try:
            self.writer_job.link(self.reader_job)
            try:
                while self.state in ['CONNECTED', 'FLUSHING']:
                    chunk = self.msrp.read_chunk()
                    if chunk.method is None: # response
                        self._handle_incoming_response(chunk)
                    elif chunk.method=='SEND':
                        self._handle_incoming_SEND(chunk)
                    elif chunk.method=='REPORT':
                        self.incoming.send(chunk)
                    else:
                        response = make_response(chunk, '501', 'Method unknown')
                        self.outgoing.send((response, None))
            except proc.LinkedExited: # writer has exited
                pass
            finally:
                self.writer_job.unlink(self.reader_job)
                self.writer_job.kill()
            self.state_logger.dbg('reader: expecting responses only')
            delay = time() - self.last_expected_response
            if delay>=0 and self.expected_responses:
                # continue read the responses until the last timeout expires
                with api.timeout(delay, None):
                    while self.expected_responses:
                        chunk = self.msrp.read_chunk()
                        if chunk.method is None:
                            self._handle_incoming_response(chunk)
                        else:
                            self.state_logger.dbg('dropping incoming %r' % chunk)
                # read whatever left in the queue
                with api.timeout(0, None):
                    while self.msrp._queue:
                        chunk = self.msrp.read_chunk()
                        if chunk.method is None:
                            self._handle_incoming_response(chunk)
                        else:
                            self.state_logger.dbg('dropping incoming %r' % chunk)
            self.state_logger.dbg('reader: done')
        except ConnectionClosedErrors, ex:
            self.state_logger.dbg('reader: exiting because of %r' % ex)
            self.incoming.send_exception(ex)
        except:
            self.state_logger.dbg('reader: losing connection because of %r' % (sys.exc_info(), ))
            self.incoming.send_exception(*sys.exc_info())
            raise
        finally:
            if not self.incoming.has_error():
                self.incoming.send_exception(ConnectionDone)
            self.msrp.loseConnection(sync=False)
            self.set_state('DONE')

    def receive_chunk(self):
        return self.incoming.wait()

    def _writer(self):
        try:
            while self.state=='CONNECTED':
                send_params = self.outgoing.wait()
                if send_params is None:
                    break
                self._write_chunk(*send_params)
            while self.state=='FLUSHING' and self.outgoing:
                send_params = self.outgoing.wait()
                if send_params is not None:
                    self._write_chunk(*send_params)
        except ConnectionClosedErrors + (proc.LinkedExited, proc.ProcExit), ex:
            self.state_logger.dbg('writer: exiting because of %r' % (ex, ))
        except:
            self.state_logger.dbg('writer: losing connection because of %r' % (sys.exc_info(), ))
            self.msrp.loseConnection(sync=false)
            raise
        finally:
            self.set_state('CLOSING')

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

        If sending is impossible raise MSRPSessionError.
        """
        if self.state != 'CONNECTED':
            raise MSRPSessionError('Cannot send chunk because MSRPSession is %s' % self.state)
        if self.msrp._disconnected_event.ready():
            raise MSRPSessionError(str(self.msrp._disconnected_event.wait()))
        self.outgoing.send((chunk, event))

    def _write_chunk(self, chunk, event=None):
        id = chunk.transaction_id
        assert id not in self.expected_responses, "MSRP transaction %r is already in progress" % id
        if event is not None:
            # since reader is in another greenlet and write() will switch the greenlets,
            # let's setup response's event and timer before write() call, just in case
            event_and_timer = [event, None]
            self.expected_responses[id] = event_and_timer
        try:
            self.msrp.write(chunk.encode())
        except Exception:
            if event is not None:
                self.expected_responses.pop(id, None)
            raise
        else:
            if event is not None:
                timeout_error = Response408Timeout if chunk.failure_report=='yes' else Response200OK
                timer = api.get_hub().schedule_call_global(self.RESPONSE_TIMEOUT, self._response_timeout, id, timeout_error)
                self.last_expected_response = time() + self.RESPONSE_TIMEOUT
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

    def make_message(self, msg, content_type):
        chunk = self.msrp.make_chunk(data=msg)
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

# TODO:
# 413 - requires special action both in reader and in writer
# continuation: #
# All MSRP endpoints MUST be able to receive the multipart/mixed [15] and multipart/alternative [15] media-types.
