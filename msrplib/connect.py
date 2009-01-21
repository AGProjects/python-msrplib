# Copyright (C) 2008 AG Projects. See LICENSE for details

from __future__ import with_statement

from twisted.internet.address import IPv4Address

from eventlet.twistedutil.protocol import GreenClientCreator, SpawnFactory
from eventlet.coros import event
from eventlet.api import timeout

from msrplib import protocol, MSRPError
from msrplib.transport import MSRPTransport, MSRPTransactionError, MSRPBadRequest
from msrplib.util import random_string
from msrplib.digest import process_www_authenticate

__all__ = ['MSRPRelaySettings', 'MSRPConnectFactory', 'MSRPAcceptFactory']

class MSRPRelaySettings(protocol.ConnectInfo):
    use_tls = True

    def __init__(self, domain, username, password, host=None, port=None, use_tls=None, credentials=None):
        protocol.ConnectInfo.__init__(self, host, use_tls=use_tls, port=port, credentials=credentials)
        self.domain = domain
        self.username = username
        self.password = password

    def __str__(self):
        result = "MSRPRelay %s://%s" % (self.scheme, self.host or self.domain)
        if self.port:
            result += ':%s' % self.port
        return result

    def __repr__(self):
        params = [self.domain, self.username, self.password, self.host, self.port]
        if params[-1] is None:
            del params[-1]
        if params[-1] is None:
            del params[-1]
        return '%s(%s)' % (type(self).__name__, ', '.join(repr(x) for x in params))

    @property
    def uri_domain(self):
       return protocol.URI(host=self.domain, port=self.port, use_tls=self.use_tls, session_id='')

class TimeoutMixin(object):

    @classmethod
    def timeout(cls):
        return timeout(cls.seconds, cls)

class MSRPTimeout(MSRPError, TimeoutMixin):
    seconds = 10

class MSRPConnectTimeout(MSRPTimeout):
    pass

class MSRPRelayConnectTimeout(MSRPTimeout):
    pass

class MSRPIncomingConnectTimeout(MSRPTimeout):
    pass

class MSRPBindSessionTimeout(MSRPTimeout):
    pass

class MSRPRelayAuthError(MSRPTransactionError):
    pass

class MSRPAuthTimeout(MSRPTransactionError, TimeoutMixin):
    code = 408
    comment = 'No response to AUTH request'
    seconds = 30

class ConnectBase(object):
    MSRPTransportClass = MSRPTransport
    SRVConnectorClass = None

    def __init__(self, *args, **kwargs):
        self.args = args
        if 'MSRPTransportClass' in kwargs:
            self.MSRPTransportClass = kwargs.pop('MSRPTransportClass')
        self.kwargs = kwargs

    def _get_state_logger(self):
        return self.kwargs.get('state_logger')

    def _set_state_logger(self, state_logger):
        self.kwargs['state_logger'] = state_logger

    state_logger = property(_get_state_logger, _set_state_logger)

    def generate_local_uri(self, port=0):
        return protocol.URI(port=port)

    def _connect(self, local_uri, remote_uri):
        from twisted.internet import reactor
        if self.state_logger:
            self.state_logger.report_connecting(remote_uri)
        creator = GreenClientCreator(reactor, self.MSRPTransportClass, local_uri, *self.args, **self.kwargs)
        connectFuncName = 'connect' + remote_uri.protocol_name
        connectFuncArgs = remote_uri.protocolArgs
        if remote_uri.host:
            args = (remote_uri.host, remote_uri.port or 2855) + connectFuncArgs
            msrp = getattr(creator, connectFuncName)(*args)
        else:
            if not remote_uri.domain:
                raise ValueError("remote_uri must have either 'host' or 'domain'")
            msrp = creator.connectSRV(remote_uri.scheme, remote_uri.domain,
                                      connectFuncName=connectFuncName,
                                      connectFuncArgs=connectFuncArgs,
                                      ConnectorClass=self.SRVConnectorClass)
        if self.state_logger:
            self.state_logger.report_connected(msrp)
        return msrp

    def cleanup(self):
        pass

class ConnectorDirect(ConnectBase):

    BOGUS_LOCAL_PORT = 12345

    def prepare(self, local_uri=None):
        if local_uri is None:
            local_uri = self.generate_local_uri(self.BOGUS_LOCAL_PORT)
        self.local_uri = local_uri
        return [self.local_uri]

    def getHost(self):
        return IPv4Address('TCP', '0.0.0.0', 0)

    def complete(self, full_remote_path):
        with MSRPConnectTimeout.timeout():
            msrp = self._connect(self.local_uri, full_remote_path[0])
            # can't do the following, because local_uri was already used in the INVITE
            #msrp.local_uri.port = msrp.getHost().port
        with MSRPBindSessionTimeout.timeout():
            msrp.bind(full_remote_path)
        return msrp

class AcceptorDirect(ConnectBase):

    def _listen(self, local_uri, handler):
        # QQQ use ip from local_uri as binding interface?
        from twisted.internet import reactor
        factory = SpawnFactory(handler, self.MSRPTransportClass, local_uri, *self.args, **self.kwargs)
        listenFuncName = 'listen' + local_uri.protocol_name
        listenFuncArgs = (local_uri.port or 0, factory) + local_uri.protocolArgs
        port = getattr(reactor, listenFuncName)(*listenFuncArgs)
        if self.state_logger:
            self.state_logger.report_listen(local_uri, port)
        return local_uri, port

    def prepare(self, local_uri=None):
        """Start listening for an incoming MSRP connection using port and
        use_tls from local_uri if provided.

        Return full local path, suitable to put in SDP a:path attribute.
        Note, that `local_uri' may be updated in place.
        """
        if local_uri is None:
            local_uri = self.generate_local_uri()
        self.transport_event = event()
        local_uri, self.listener = self._listen(local_uri, self.transport_event.send)
        # QQQ update local_uri.host as well?
        local_uri.port = self.listener.getHost().port
        self.local_uri = local_uri
        return [local_uri]

    def getHost(self):
        return self.listener.getHost()

    def _accept(self):
        msrp = self.transport_event.wait()
        if self.state_logger:
            self.state_logger.report_accepted(self.local_uri, msrp)
        return msrp

    def complete(self, full_remote_path):
        """Accept an incoming MSRP connection and bind it.
        Return MSRPTransport instance.
        """
        try:
            with MSRPIncomingConnectTimeout.timeout():
                msrp = self._accept()
        finally:
            self.cleanup()
        with MSRPBindSessionTimeout.timeout():
            msrp.accept_binding(full_remote_path)
        return msrp

    def cleanup(self):
        try:
            self.listener.stopListening()
            del self.listener
            del self.transport_event
        except AttributeError:
            pass

def _deliver_chunk(msrp, chunk):
    msrp.write_chunk(chunk)
    with MSRPAuthTimeout.timeout():
        response = msrp._wait_chunk()
    if response.method is not None:
        raise MSRPBadRequest
    if response.transaction_id!=chunk.transaction_id:
        raise MSRPBadRequest
    return response

class RelayConnectBase(ConnectBase):

    def __init__(self, relay, *args, **kwargs):
        self.relay = relay
        ConnectBase.__init__(self, *args, **kwargs)

    def _relay_connect(self, local_uri):
        conn = self._connect(local_uri, self.relay)
        local_uri.port = conn.getHost().port
        msrpdata = protocol.MSRPData(method="AUTH", transaction_id=random_string(12))
        msrpdata.add_header(protocol.ToPathHeader([self.relay.uri_domain]))
        msrpdata.add_header(protocol.FromPathHeader([local_uri]))
        response = _deliver_chunk(conn, msrpdata)
        if response.code == 401:
            www_authenticate = response.headers["WWW-Authenticate"]
            auth, rsp_auth = process_www_authenticate(self.relay.username, self.relay.password, "AUTH",
                                                      str(self.relay.uri_domain), **www_authenticate.decoded)
            msrpdata.transaction_id = random_string(12)
            msrpdata.add_header(protocol.AuthorizationHeader(auth))
            response = _deliver_chunk(conn, msrpdata)
        if response.code != 200:
            raise MSRPRelayAuthError(comment=response.comment, code=response.code)
        conn.use_path(list(response.headers["Use-Path"].decoded))
        #print 'Reserved session at MSRP relay %s:%d, Use-Path: %s' % (relaysettings.host, relaysettings.port, conn.local_uri)
        return conn

    def _relay_connect_timeout(self, local_uri):
        with MSRPRelayConnectTimeout.timeout():
            return self._relay_connect(local_uri)

    def prepare(self, local_uri=None):
        if local_uri is None:
            local_uri = self.generate_local_uri()
        self.msrp = self._relay_connect_timeout(local_uri)
        return self.msrp.full_local_path

    def getHost(self):
        return self.msrp.getHost()

    def cleanup(self):
        try:
            self.msrp.loseConnection()
            del self.msrp
        except AttributeError:
            pass

class ConnectorRelay(RelayConnectBase):

    def complete(self, full_remote_path):
        try:
            with MSRPBindSessionTimeout.timeout():
                self.msrp.bind(full_remote_path)
            return self.msrp
        finally:
            del self.msrp

class AcceptorRelay(RelayConnectBase):

    def complete(self, full_remote_path):
        try:
            with MSRPBindSessionTimeout.timeout():
                self.msrp.accept_binding(full_remote_path)
            return self.msrp
        finally:
            del self.msrp

class MSRPConnectFactory:
    ConnectorDirect = ConnectorDirect
    ConnectorRelay = ConnectorRelay

    @classmethod
    def new(cls, relay, *args, **kwargs):
        if relay is None:
            return cls.ConnectorDirect(*args, **kwargs)
        return cls.ConnectorRelay(relay, *args, **kwargs)

class MSRPAcceptFactory(object):
    AcceptorDirect = AcceptorDirect
    AcceptorRelay = AcceptorRelay

    @classmethod
    def new(cls, relay, *args, **kwargs):
        if relay is None:
            return cls.AcceptorDirect(*args, **kwargs)
        return cls.AcceptorRelay(relay, *args, **kwargs)

