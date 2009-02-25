# Copyright (C) 2008-2009 AG Projects. See LICENSE for details

from __future__ import with_statement
import sys
from time import time
from twisted.internet.error import ConnectionClosed, ConnectionDone
from gnutls.errors import GNUTLSError
from eventlet import api, coros, proc
from eventlet.twistedutil.protocol import ValueQueue

from msrplib import protocol, MSRPError
from msrplib.transport import make_response, MSRPTransactionError

ConnectionClosedErrors = (ConnectionClosed, GNUTLSError)

class MSRPSessionError(MSRPError):
    pass

class MSRPBadContentType(MSRPTransactionError):
    code = 415
    comment = 'Unsupported media type'

class LocalResponse(MSRPTransactionError):

    def __repr__(self):
        return '<LocalResponse %s %s>' % (self.code, self.comment)

Response200OK = LocalResponse("OK", 200)
Response408Timeout = LocalResponse("Timed out while waiting for transaction response", 408)


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
        # to responses and success reports. (XXX it could now discard incoming data chunks
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
            response_cb, timer = self.expected_responses.pop(chunk.transaction_id)
        except KeyError:
            pass
        else:
            if timer is not None:
                timer.cancel()
            response_cb(chunk)

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
        response_cb from self.expected_responses and send the response there.
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
            self.msrp.loseConnection(sync=False)
            raise
        finally:
            self.set_state('CLOSING')

    def send_chunk(self, chunk, response_cb=None):
        """Send `chunk'. Report the result via `response_cb'.

        When `response_cb' argument is present, it will be used to report
        the response to the caller. When a response is received or generated
        locally, `response_cb' is called with one argument. The function
        must do something quickly and must not block, because otherwise it would
        the reader greenlet.

        If no response was received after RESPONSE_TIMEOUT seconds,
        * 408 response is generated if Failure-Report was 'yes' or absent
        * 200 response is generated if Failure-Report was 'partial' or 'no'

        Note that it's rather wasteful to provide `response_cb' argument other than None
        for chunks with Failure-Report='no' since it will always fire 30 seconds later
        with 200 result (unless the other party is broken and ignores Failure-Report header)

        If sending is impossible raise MSRPSessionError.
        """
        assert id not in self.expected_responses, "MSRP transaction %r is already in progress" % id
        if response_cb is not None and not callable(response_cb):
            raise TypeError('response_cb must be callable: %r' % (response_cb, ))
        if self.state != 'CONNECTED':
            raise MSRPSessionError('Cannot send chunk because MSRPSession is %s' % self.state)
        if self.msrp._disconnected_event.ready():
            raise MSRPSessionError(str(self.msrp._disconnected_event.wait()))
        self.outgoing.send((chunk, response_cb))

    def _write_chunk(self, chunk, response_cb=None):
        id = chunk.transaction_id
        assert id not in self.expected_responses, "MSRP transaction %r is already in progress" % id
        if response_cb is not None:
            # since reader is in another greenlet and write() will switch the greenlets,
            # let's setup response_cb and timer before write() call, just in case
            cb_and_timer = [response_cb, None]
            self.expected_responses[id] = cb_and_timer
        try:
            self.msrp.write(chunk.encode())
        except Exception:
            if response_cb is not None:
                self.expected_responses.pop(id, None)
            raise
        else:
            if response_cb is not None:
                timeout_error = Response408Timeout if chunk.failure_report=='yes' else Response200OK
                timer = api.get_hub().schedule_call_global(self.RESPONSE_TIMEOUT, self._response_timeout, id, timeout_error)
                self.last_expected_response = time() + self.RESPONSE_TIMEOUT
                cb_and_timer[1] = timer

    def _response_timeout(self, id, timeout_error):
        response_cb, timer = self.expected_responses.pop(id, (None, None))
        if response_cb is not None:
            response_cb(timeout_error)
            if timer is not None:
                timer.cancel()

    def deliver_chunk(self, chunk, event=None):
        """Send chunk, block until transaction response is received
        (if Failure-Report header is not 'no'). Return the transaction response
        if it's a success, raise MSRPTransactionError if it's not.

        If chunk's Failure-Report is 'no', return None immediatelly.
        """
        if chunk.failure_report!='no' and event is None:
            event = coros.event()
        self.send_chunk(chunk, event.send)
        if event is not None:
            response = event.wait()
            if isinstance(response, Exception):
                raise response
            elif 200 <= response.code <= 299:
                return response
            raise MSRPTransactionError(comment=response.comment, code=response.code)

    def make_message(self, msg, content_type, message_id=None):
        chunk = self.msrp.make_chunk(data=msg, message_id=message_id)
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