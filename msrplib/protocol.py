# Copyright (C) 2008-2009 AG Projects. See LICENSE for details

from collections import deque
import re
import random

from twisted.protocols.basic import LineReceiver
from application.system import default_host_ip


class MSRPError(Exception):
    pass

class ParsingError(MSRPError):
    pass

class HeaderParsingError(ParsingError):

    def __init__(self, header):
        self.header = header
        ParsingError.__init__(self, "Error parsing %s header" % header)

class MSRPHeaderMeta(type):
    header_classes = {}

    def __init__(cls, name, bases, dict):
        type.__init__(cls, name, bases, dict)
        try:
            cls.header_classes[dict["name"]] = name
        except KeyError:
            pass

class MSRPHeader(object):
    __metaclass__ = MSRPHeaderMeta

    def __new__(cls, name, value):
        if isinstance(value, str) and name in MSRPHeaderMeta.header_classes:
            cls = eval(MSRPHeaderMeta.header_classes[name])
        return object.__new__(cls)

    def __init__(self, name, value):
        self.name = name
        if isinstance(value, str):
            self.encoded = value
        else:
            self.decoded = value

    def _raise_error(self):
        raise HeaderParsingError(self.name)

    def _get_encoded(self):
        if self._encoded is None:
            self._encoded = self._encode(self._decoded)
        return self._encoded

    def _set_encoded(self, encoded):
        self._encoded = encoded
        self._decoded = None

    encoded = property(_get_encoded, _set_encoded)

    def _get_decoded(self):
        if self._decoded is None:
            self._decoded = self._decode(self._encoded)
        return self._decoded

    def _set_decoded(self, decoded):
        self._decoded = decoded
        self._encoded = None

    decoded = property(_get_decoded, _set_decoded)

    def _decode(self, encoded):
        return encoded

    def _encode(self, decoded):
        return decoded

class MSRPNamedHeader(MSRPHeader):

    def __new__(cls, *args):
        if len(args) == 1:
            value = args[0]
        else:
            value = args[1]
        return MSRPHeader.__new__(cls, cls.name, value)

    def __init__(self, *args):
        if len(args) == 1:
            value = args[0]
        else:
            value = args[1]
        MSRPHeader.__init__(self, self.name, value)

class URIHeader(MSRPNamedHeader):

    def _decode(self, encoded):
        try:
            return deque(parse_uri(uri) for uri in encoded.split(" "))
        except ParsingError:
            self._raise_error()

    def _encode(self, decoded):
        return " ".join([str(uri) for uri in decoded])

class IntegerHeader(MSRPNamedHeader):

    def _decode(self, encoded):
        try:
            return int(encoded)
        except ValueError:
            self._raise_error()

    def _encode(self, decoded):
        return str(decoded)

class DigestHeader(MSRPNamedHeader):

    def _decode(self, encoded):
        try:
            algo, params = encoded.split(" ", 1)
        except ValueError:
            self._raise_error()
        if algo != "Digest":
            self._raise_error()
        try:
            param_dict = dict((x.strip('"') for x in param.split("=", 1)) for param in params.split(", "))
        except:
            self._raise_error()
        return param_dict

    def _encode(self, decoded):
        return "Digest " + ", ".join(['%s="%s"' % tup for tup in decoded.iteritems()])

class ToPathHeader(URIHeader):
    name = "To-Path"

class FromPathHeader(URIHeader):
    name = "From-Path"

class MessageIDHeader(MSRPNamedHeader):
    name = "Message-ID"

class SuccessReportHeader(MSRPNamedHeader):
    name = "Success-Report"

    def _decode(self, encoded):
        if encoded not in ["yes", "no"]:
            self._raise_error()
        return encoded

class FailureReportHeader(MSRPNamedHeader):
    name = "Failure-Report"

    def _decode(self, encoded):
        if encoded not in ["yes", "no", "partial"]:
            self._raise_error()
        return encoded

class ByteRangeHeader(MSRPNamedHeader):
    name = "Byte-Range"

    def _decode(self, encoded):
        try:
            rest, total = encoded.split("/")
            fro, to = rest.split("-")
            fro = int(fro)
        except ValueError:
            self._raise_error()
        try:
            to = int(to)
        except ValueError:
            if to != "*":
                self._raise_error()
            to = None
        try:
            total = int(total)
        except ValueError:
            if total != "*":
                self._raise_error()
            total = None
        return (fro, to, total)

    def _encode(self, decoded):
        fro, to, total = decoded
        if to is None:
            to = "*"
        if total is None:
            total = "*"
        return "%s-%s/%s" % (fro, to, total)

    @property
    def fro(self):
        return self.decoded[0]

    @property
    def to(self):
        return self.decoded[1]

    @property
    def total(self):
        return self.decoded[2]

class StatusHeader(MSRPNamedHeader):
    name = "Status"

    def _decode(self, encoded):
        try:
            namespace, rest = encoded.split(" ", 1)
        except ValueError:
            self._raise_error()
        if namespace != "000":
            self._raise_error()
        rest_sp = rest.split(" ", 1)
        try:
            if len(rest_sp[0]) != 3:
                raise ValueError
            code = int(rest_sp[0])
        except ValueError:
            self._raise_error()
        try:
            comment = rest_sp[1]
        except IndexError:
            comment = None
        return (code, comment)

    def _encode(self, decoded):
        code, comment = decoded
        encoded = "000 %03d" % code
        if comment is not None:
            encoded += " %s" % comment
        return encoded

    @property
    def code(self):
        return self.decoded[0]

    @property
    def comment(self):
        return self.decoded[1]

class ExpiresHeader(IntegerHeader):
    name = "Expires"

class MinExpiresHeader(IntegerHeader):
    name = "Min-Expires"

class MaxExpiresHeader(IntegerHeader):
    name = "Max-Expires"

class UsePathHeader(URIHeader):
    name = "Use-Path"

class WWWAuthenticateHeader(DigestHeader):
    name = "WWW-Authenticate"

class AuthorizationHeader(DigestHeader):
    name = "Authorization"

class AuthenticationInfoHeader(MSRPNamedHeader):
    name = "Authentication-Info"

    def _decode(self, encoded):
        try:
            param_dict = dict((x.strip('"') for x in param.split("=", 1)) for param in encoded.split(", "))
        except:
            self._raise_error()
        return param_dict

    def _encode(self, decoded):
        return ", ".join(['%s="%s"' % tup for tup in decoded.iteritems()])

class ContentTypeHeader(MSRPNamedHeader):
    name = "Content-Type"

class ContentIDHeader(MSRPNamedHeader):
    name = "Content-ID"

class ContentDescriptionHeader(MSRPNamedHeader):
    name = "Content-Description"

class ContentDispositionHeader(MSRPNamedHeader):
    name = "Content-Disposition"

    def _decode(self, encoded):
        try:
            sp = encoded.split(";")
            disposition = sp[0]
            parameters = dict(param.split("=", 1) for param in sp[1:])
        except:
            self._raise_error()
        return [disposition, parameters]

    def _encode(self, decoded):
        disposition, parameters = decoded
        return ";".join([disposition] + ["%s=%s" % pair for pair in parameters.iteritems()])

class MSRPData(object):

    # for chunks that are generated locally by splitting a big incoming chunk
    # segment will be a sequential index, starting with 1
    segment = None
    final = True

    def __init__(self, transaction_id, method=None, code=None, comment=None, headers=None, data='', contflag='$'):
        self.transaction_id = transaction_id
        self.method = method
        self.code = code
        self.comment = comment
        if headers is None:
            headers = {}
        self.headers = headers
        self.data = data
        self.contflag = contflag

    def copy(self):
        chunk = self.__class__(self.transaction_id)
        chunk.__dict__.update(self.__dict__)
        chunk.headers = dict(self.headers.items())
        return chunk

    def __str__(self):
        if self.method is None:
            description = "MSRP %s %s" % (self.transaction_id, self.code)
            if self.comment is not None:
                description += " %s" % self.comment
        else:
            description = "MSRP %s %s" % (self.transaction_id, self.method)
        return description

    def __repr__(self):
        klass = type(self).__name__
        if self.method is None:
            description = "%s %s" % (self.transaction_id, self.code)
            if self.comment is not None:
                description += " %s" % self.comment
        else:
            description = "%s %s" % (self.transaction_id, self.method)
        if self.message_id is not None:
            description += ' Message-ID=%s' % self.message_id
        for key, value in self.headers.items():
            description += ' %s=%r' % (key, value.encoded)
        description += ' len=%s' % self.size
        return '<%s at %s %s %s>' % (klass, hex(id(self)), description, self.contflag)

    def __eq__(self, other):
        if not isinstance(other, MSRPData):
            return False
        return self.encode()==other.encode()

    def add_header(self, header):
        self.headers[header.name] = header

    def verify_headers(self):
        try: # Decode To-/From-path headers first to be able to send responses
            self.headers["To-Path"].decoded
            self.headers["From-Path"].decoded
        except KeyError, e:
            raise HeaderParsingError(e.args[0])
        for header in self.headers.itervalues():
            header.decoded

    @property
    def content_type(self):
        x = self.headers.get('Content-Type')
        if x is None:
            return x
        return x.decoded

    @property
    def message_id(self):
        x = self.headers.get('Message-ID')
        if x is None:
            return x
        return x.decoded

    @property
    def byte_range(self):
        x = self.headers.get('Byte-Range')
        if x is None:
            return x
        return x.decoded

    @property
    def status(self):
        return self.headers.get('Status')

    @property
    def failure_report(self):
        if "Failure-Report" in self.headers:
            return self.headers["Failure-Report"].decoded
        else:
            return "yes"

    @property
    def success_report(self):
        if "Success-Report" in self.headers:
            return self.headers["Success-Report"].decoded
        else:
            return "no"

    @property
    def size(self):
        return len(self.data)

    def encode_start(self):
        data = []
        if self.method is not None:
            data.append("MSRP %(transaction_id)s %(method)s" % self.__dict__)
        else:
            data.append("MSRP %(transaction_id)s %(code)03d" % self.__dict__ + (self.comment is not None and " %s" % self.comment or ""))
        headers = self.headers.copy()
        data.append("To-Path: %s" % headers.pop("To-Path").encoded)
        data.append("From-Path: %s" % headers.pop("From-Path").encoded)
        for hnameval in [(hname, headers.pop(hname).encoded) for hname in headers.keys() if not hname.startswith("Content-")]:
            data.append("%s: %s" % hnameval)
        for hnameval in [(hname, headers.pop(hname).encoded) for hname in headers.keys() if hname != "Content-Type"]:
            data.append("%s: %s" % hnameval)
        if len(headers) > 0:
            data.append("Content-Type: %s" % headers["Content-Type"].encoded)
            data.append("")
            data.append("")
        return "\r\n".join(data)

    def encode_end(self, continuation):
        return "\r\n-------%s%s\r\n" % (self.transaction_id, continuation)

    def encode(self):
        return self.encode_start() + self.data + self.encode_end(self.contflag)

class MSRPProtocol(LineReceiver):
    MAX_LENGTH = 16384
    MAX_LINES = 64

    def __init__(self, recepient):
        self._chunk_header = ''
        self._recepient = recepient
        self._reset()

    def _reset(self):
        self._chunk_header = ''
        self.data = None
        self.line_count = 0

    def connectionMade(self):
        self._recepient._got_transport(self.transport)

    def lineReceived(self, line):
        if self.data:
            if len(line) == 0:
                self.term_buf_len = 12 + len(self.data.transaction_id)
                self.term_buf = ""
                self.term = re.compile("^(.*)\r\n-------%s([$#+])\r\n(.*)$" % re.escape(self.data.transaction_id), re.DOTALL)
                self._recepient.logger.received_new_chunk(self._chunk_header+self.delimiter, self.transport, chunk=self.data)
                self._recepient._data_start(self.data)
                self.setRawMode()
            else:
                match = self.term.match(line)
                if match:
                    continuation = match.group(1)
                    self._recepient.logger.received_new_chunk(self._chunk_header, self.transport, chunk=self.data)
                    self._recepient.logger.received_chunk_end(line+self.delimiter, self.transport, transaction_id=self.data.transaction_id)
                    self._recepient._data_start(self.data)
                    self._recepient._data_end(continuation)
                    self._reset()
                    # This line is only here because it allows the subclass MSRPPRotocol_withLogging
                    # to know that the packet ended. In need of redesign. -Luci
                    self.setLineMode('')
                else:
                    self._chunk_header += line+self.delimiter
                    self.line_count += 1
                    if self.line_count > self.MAX_LINES:
                        self._recepient.logger.received_illegal_data(self._chunk_header, self.transport)
                        self._reset()
                        return
                    try:
                        hname, hval = line.split(": ", 2)
                    except ValueError:
                        return # let this pass silently, we'll just not read this line
                    else:
                        self.data.add_header(MSRPHeader(hname, hval))
        else: # we received a new message
            try:
                msrp, transaction_id, rest = line.split(" ", 2)
            except ValueError:
                self._recepient.logger.received_illegal_data(line+self.delimiter, self.transport)
                return # drop connection?
            if msrp != "MSRP":
                self._recepient.logger.received_illegal_data(line+self.delimiter, self.transport)
                return # drop connection?
            method, code, comment = None, None, None
            rest_sp = rest.split(" ", 1)
            try:
                if len(rest_sp[0]) != 3:
                    raise ValueError
                code = int(rest_sp[0])
            except ValueError: # we have a request
                method = rest_sp[0]
            else: # we have a response
                if len(rest_sp) > 1:
                    comment = rest_sp[1]
            self.data = MSRPData(transaction_id, method, code, comment)
            self.term = re.compile("^-------%s([$#+])$" % re.escape(transaction_id))
            self._chunk_header = line+self.delimiter

    def lineLengthExceeded(self, line):
        self._reset()

    def rawDataReceived(self, data):
        match_data = self.term_buf + data
        match = self.term.match(match_data)
        if match: # we got the last data for this message
            contents, continuation, extra = match.groups()
            contents = contents[len(self.term_buf):]
            if contents:
                self._recepient.logger.received_chunk_data(contents, self.transport, transaction_id=self.data.transaction_id)
                self._recepient._data_write(contents, final=True)
            self._recepient.logger.received_chunk_end('\r\n-------%s%s\r\n' % (self.data.transaction_id, continuation), self.transport, transaction_id=self.data.transaction_id)
            self._recepient._data_end(continuation)
            self._reset()
            self.setLineMode(extra)
        else:
            self._recepient.logger.received_chunk_data(data, self.transport, transaction_id=self.data.transaction_id)
            self._recepient._data_write(data, final=False)
            self.term_buf = match_data[-self.term_buf_len:]

    def connectionLost(self, reason):
        self._recepient._connectionLost(reason)


_re_uri = re.compile("^(?P<scheme>.*?)://(((?P<user>.*?)@)?(?P<host>.*?)(:(?P<port>[0-9]+?))?)(/(?P<session_id>.*?))?;(?P<transport>.*?)(;(?P<parameters>.*))?$")
def parse_uri(uri_str):
    match = _re_uri.match(uri_str)
    if match is None:
        raise ParsingError("Cannot parse URI")
    uri_params = match.groupdict()
    if uri_params["port"] is not None:
        uri_params["port"] = int(uri_params["port"])
    if uri_params["parameters"] is not None:
        try:
            uri_params["parameters"] = dict(param.split("=") for param in uri_params["parameters"].split(";"))
        except ValueError:
            raise ParsingError("Cannot parse URI parameters")
    scheme = uri_params.pop("scheme")
    if scheme == "msrp":
        uri_params["use_tls"] = False
    elif scheme == "msrps":
        uri_params["use_tls"] = True
    else:
        raise ParsingError("Invalid scheme user in URI: %s" % scheme)
    if uri_params["transport"] != "tcp":
        raise ParsingError('Invalid transport in URI, only "tcp" is accepted: %s' % uri_params["transport"])
    return URI(**uri_params)

class ConnectInfo(object):
    host = None
    use_tls = True
    port = 2855

    def __init__(self, host=None, use_tls=None, port=None, credentials=None):
        if host is not None:
            self.host = host
        if use_tls is not None:
            self.use_tls = use_tls
        if port is not None:
            self.port = port
        self.credentials = credentials
        if self.use_tls and self.credentials is None:
            from gnutls.interfaces.twisted import X509Credentials
            self.credentials = X509Credentials(None, None)

    @property
    def scheme(self):
        if self.use_tls:
            return 'msrps'
        else:
            return 'msrp'

    @property
    def protocol_name(self):
        if self.use_tls:
            return 'TLS'
        else:
            return 'TCP'

    @property
    def protocolArgs(self):
        if self.use_tls:
            return (self.credentials,)
        return ()


# use TLS_URI and TCP_URI ?
class URI(ConnectInfo):
    host = default_host_ip

    def __init__(self, host=None, use_tls=None, user=None, port=None,
                 session_id=None, transport="tcp", parameters=None,
                 credentials=None):
        ConnectInfo.__init__(self, host, use_tls=use_tls, port=port, credentials=credentials)
        self.user = user
        if session_id is None:
            session_id = '%x' % random.getrandbits(80)
        self.session_id = session_id
        self.transport = transport
        if parameters is None:
            self.parameters = {}
        else:
            self.parameters = parameters

    def __repr__(self):
        params = [self.host, self.use_tls, self.user, self.port, self.session_id, self.transport, self.parameters]
        defaults = [False, None, None, None, 'tcp', {}]
        while defaults and params[-1]==defaults[-1]:
            del params[-1]
            del defaults[-1]
        return '%s(%s)' % (self.__class__.__name__, ', '.join(`x` for x in params))

    def __str__(self):
        uri_str = []
        if self.use_tls:
            uri_str.append("msrps://")
        else:
            uri_str.append("msrp://")
        if self.user:
            uri_str.extend([self.user, "@"])
        uri_str.append(self.host)
        if self.port:
            uri_str.extend([":", str(self.port)])
        if self.session_id:
            uri_str.extend(["/", self.session_id])
        uri_str.extend([";", self.transport])
        for key, value in self.parameters.iteritems():
            uri_str.extend([";", key, "=", value])
        return "".join(uri_str)

    def __eq__(self, other):
        """MSRP URI comparison according to section 6.1 of RFC 4975"""
        if self is other:
            return True
        try:
            if self.use_tls != other.use_tls:
                return False
            if self.host.lower() != other.host.lower():
                return False
            if self.port != other.port:
                return False
            if self.session_id != other.session_id:
                return False
            if self.transport.lower() != other.transport.lower():
                return False
        except AttributeError:
            return False
        return True

    def __ne__(self, other):
        return not self == other

    def __hash__(self):
        return hash((self.use_tls, self.host.lower(), self.port, self.session_id, self.transport.lower()))


if __name__ == '__main__':
    import sys
    print parse_uri(sys.argv[1])
