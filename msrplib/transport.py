# Copyright (C) 2008-2009 AG Projects. See LICENSE for details

import random
from application import log
from twisted.internet.error import ConnectionDone
from eventlet.twistedutil.protocol import GreenTransportBase

from msrplib import protocol, MSRPError
from msrplib.trafficlog import Logger


class ChunkParseError(MSRPError):
    """Failed to parse incoming chunk"""

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

class MSRPBadRequest(MSRPTransactionError):
    code = 400
    comment = 'Bad Request'

    def __str__(self):
        return 'Remote party sent bogus data'

class MSRPNoSuchSessionError(MSRPTransactionError):
    code = 481
    comment = 'No such session'

data_start, data_end, data_write, data_final_write = xrange(4)

class MSRPProtocol_withLogging(protocol.MSRPProtocol):

    _new_chunk = False

    def rawDataReceived(self, data):
        self._recepient.logger.report_in(data, self.transport)
        protocol.MSRPProtocol.rawDataReceived(self, data)

    def lineReceived(self, line):
        self._recepient.logger.report_in(line+self.delimiter, self.transport, self._new_chunk)
        self._new_chunk = False
        protocol.MSRPProtocol.lineReceived(self, line)

    def connectionLost(self, reason):
        msg = 'Closed connection to %s:%s' % (self.transport.getPeer().host, self.transport.getPeer().port)
        if not isinstance(reason.value, ConnectionDone):
            msg += ' (%s)' % reason.getErrorMessage()
        self._recepient.logger.info(msg)
        protocol.MSRPProtocol.connectionLost(self, reason)

    def setLineMode(self, extra):
        self._new_chunk = True
        self._recepient.logger.report_in('', self.transport, packet_done=True)
        return protocol.MSRPProtocol.setLineMode(self, extra)


def make_report(chunk, code, comment):
    if chunk.success_report == 'yes' or (chunk.failure_report in ('yes', 'partial') and code != 200):
        report = protocol.MSRPData(transaction_id='%x' % random.getrandbits(64), method='REPORT')
        report.add_header(protocol.ToPathHeader(chunk.headers['From-Path'].decoded))
        report.add_header(protocol.FromPathHeader([chunk.headers['To-Path'].decoded[0]]))
        report.add_header(protocol.StatusHeader('000 %d %s' % (code, comment)))
        report.add_header(protocol.MessageIDHeader(chunk.message_id))
        byterange = chunk.headers.get('Byte-Range')
        if byterange is None:
            start = 1
            total = chunk.size
        else:
            start, end, total = byterange.decoded
        report.add_header(protocol.ByteRangeHeader((start, start+chunk.size-1, total)))
        return report
    else:
        return None


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


class MSRPTransport(GreenTransportBase):
    protocol_class = MSRPProtocol_withLogging

    def __init__(self, local_uri, logger, use_acm=False):
        GreenTransportBase.__init__(self)
        if local_uri is not None and not isinstance(local_uri, protocol.URI):
            raise TypeError('Not MSRP URI instance: %r' % (local_uri, ))
        # The following members define To-Path and From-Path headers as following:
        # * Outgoing request:
        #   From-Path: local_uri
        #   To-Path: local_path + remote_path + [remote_uri]
        # * Incoming request:
        #   From-Path: remote_path + remote_uri
        #   To-Path: remote_path + local_path + [local_uri] # XXX
        self.local_uri = local_uri
        if logger is None:
            logger = Logger()
        self.logger = logger
        self.local_path = []
        self.remote_uri = None
        self.remote_path = []
        self.use_acm = use_acm
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
                   contflag=None, start=1, end=None, length=None, message_id=None):
        """Make a new MSRPData object with proper From-Path and To-Path headers set up.
        In addition add Byte-Range and Message-ID headers.
        """
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
        chunk.add_header(protocol.ByteRangeHeader((start, end if length <= 2048 else None, length)))
        if message_id is None:
            chunk.add_header(protocol.MessageIDHeader('%x' % random.getrandbits(64)))
        else:
            chunk.add_header(protocol.MessageIDHeader(message_id))
        # Byte-Range and Message-ID are neccessary because otherwise msrprelay does not work
        if method=='SEND':
            chunk.data = data
            chunk.contflag = contflag
        else:
            chunk.data = ''
            chunk.contflag = '$'
        return chunk

    def _data_start(self, data):
        self._queue.send((data_start, data))

    def _data_end(self, continuation):
        self._queue.send((data_end, continuation))

    def _data_write(self, contents, final):
        if final:
            self._queue.send((data_final_write, contents))
        else:
            self._queue.send((data_write, contents))

    def write(self, bytes, wait=True):
        """Write `bytes' to the socket. If `wait' is true, wait for an operation to complete"""
        self.logger.report_out(bytes, self.transport)
        return GreenTransportBase.write(self, bytes, wait)

    def write_chunk(self, chunk, wait=True):
        trailer = chunk.encode_start()
        footer = chunk.encode_end(chunk.contflag)
        self.write(trailer+chunk.data+footer, wait=wait)
        self.logger.sent_new_chunk(trailer, self, chunk=chunk)
        if chunk.data:
            self.logger.sent_chunk_data(chunk.data, self, chunk.transaction_id)
        self.logger.sent_chunk_end(footer, self, chunk.transaction_id)

    def read_chunk(self, size=None):
        """Wait for a new chunk and return it.
        If there was an error, close the connection and raise ChunkParseError.

        In case of unintelligible input, lose the connection and return None.
        When the connection is closed, raise the reason of the closure (e.g. ConnectionDone).

        If the data already read exceeds `size', stop reading the data and return
        a "virtual" chunk, i.e. the one that does not actually correspond the the real
        MSRP chunk. Such chunks have Byte-Range header changed to match the number of
        bytes read and continuation that is '+'; they also possess 'segment' attribute,
        an integer, starting with 1 and increasing with every new segment of the chunk.

        Note, that `size' only hints when to interrupt the segment but does not affect
        how the data is read from socket. You may have segments bigger than `size' and it's
        legal to set `size' to zero (which would mean return a chunk as long as you get
        some data, regardless how small)
        """
        if self._msrpdata is None:
            func, msrpdata = self._wait()
            if func!=data_start:
                self.logger.debug('Bad data: %r %r' % (func, msrpdata))
                self.loseConnection()
                raise ChunkParseError
        else:
            msrpdata = self._msrpdata
        data = msrpdata.data
        func, param = self._wait()
        while func==data_write:
            data += param
            if size is not None and len(data)>=size:
                if msrpdata.segment is None:
                    msrpdata.segment = 1
                else:
                    msrpdata.segment += 1
                last_chunk = msrpdata.byte_range[0]+len(data)-1 == msrpdata.byte_range[2]
                self._msrpdata = msrpdata.copy()
                msrpdata.data = data
                msrpdata.contflag = '+' if last_chunk else '$'
                msrpdata.final = last_chunk
                fro, to, total = msrpdata.byte_range
                msrpdata.add_header(protocol.ByteRangeHeader((fro, None, total)))
                if last_chunk:
                    self._msrpdata = msrpdata
                    return self.read_chunk(size)
                else:
                    self._msrpdata.add_header(protocol.ByteRangeHeader((fro+msrpdata.size, None, total)))
                self.logger.debug('read_chunk -> (virtual) %r' % (msrpdata, ))
                return msrpdata
            func, param = self._wait()
        if func == data_final_write:
            data += param
            func, param = self._wait()
        if func != data_end:
            self.logger.debug('Bad data: %r %s' % (func, repr(param)[:100]))
            self.loseConnection()
            raise ChunkParseError
        if param not in "$+#":
            self.logger.debug('Bad data: %r %s' % (func, repr(param)[:100]))
            self.loseConnection()
            raise ChunkParseError
        msrpdata.data = data
        msrpdata.contflag = param
        self._msrpdata = None
        self.logger.debug('read_chunk -> %r' % (msrpdata, ))
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
        self.write_chunk(chunk)
        response = self.read_chunk()
        if response.code != 200:
            self.loseConnection(wait=False)
            raise MSRPNoSuchSessionError('Cannot bind session: %s' % response)

    def write_response(self, chunk, code, comment, wait=True):
        """Generate and write the response, lose the connection in case of error"""
        try:
            response = make_response(chunk, code, comment)
        except ChunkParseError, ex:
            log.error('Failed to generate a response: %s' % ex)
            self.loseConnection(wait=False)
            raise
        except Exception:
            log.error('Failed to generate a response')
            log.err()
            self.loseConnection(wait=False)
            raise
        else:
            if response is not None:
                self.write_chunk(response, wait=wait)

    def accept_binding(self, full_remote_path):
        self._set_full_remote_path(full_remote_path)
        chunk = self.read_chunk()
        error = self.check_incoming_SEND_chunk(chunk)
        if error is None:
            code, comment = 200, 'OK'
        else:
            code, comment = error.code, error.comment
        self.write_response(chunk, code, comment)
        if 'Content-Type' in chunk.headers or chunk.size>0:
            # deliver chunk to read_chunk
            data = chunk.data
            chunk.data = ''
            self._data_start(chunk)
            self._data_write(data, final=True)
            self._data_end(chunk.contflag)

    def check_incoming_SEND_chunk(self, chunk):
        """Check the 'To-Path' and 'From-Path' of the incoming SEND chunk.
        Return None is the paths are valid for this connection.
        If an error is detected and MSRPError is created and returned.
        """
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
        # Match only session ID when use_acm is set (http://tools.ietf.org/html/draft-ietf-simple-msrp-sessmatch-05)
        if self.use_acm:
            if ToPath[0].session_id != ExpectedTo[0].session_id:
                log.error('To-Path: expected session_id %s, got %s' % (ExpectedTo[0].session_id, ToPath[0].session_id))
                return MSRPNoSuchSessionError('Invalid To-Path')
        else:
            if ToPath != ExpectedTo:
                log.error('To-Path: expected %r, got %r' % (ExpectedTo, ToPath))
                return MSRPNoSuchSessionError('Invalid To-Path')
        if FromPath != ExpectedFrom:
            log.error('From-Path: expected %r, got %r' % (ExpectedFrom, FromPath))
            return MSRPNoSuchSessionError('Invalid From-Path')

