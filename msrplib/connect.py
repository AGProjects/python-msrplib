# Copyright (C) 2008 AG Projects. See LICENSE for details 

from __future__ import with_statement
from application.system import default_host_ip

from eventlet.twistedutil.protocol import GreenClientCreator, SpawnFactory
from eventlet.coros import event
from eventlet.api import timeout

from msrplib import protocol, MSRPError
from msrplib.transport import MSRPSession, MSRPTransactionError, MSRPBadRequest
from msrplib.util import random_string
from msrplib.digest import process_www_authenticate

__all__ = ['MSRPRelaySettings', 'MSRPConnectFactory', 'MSRPAcceptFactory']

class MSRPRelaySettings(object):
    port = 2855
    use_tls = True

    def __init__(self, domain, username, password, host=None, port=None, use_tls=None):
        self.domain = domain
        self.username = username
        self.password = password
        self.host = host
        if port is not None:
            self.port = port
        if use_tls is not None:
            self.use_tls = use_tls

    def __repr__(self):
        params = [self.domain, self.username, self.password, self.host, self.port]
        if params[-1] is None:
            del params[-1]
        if params[-1] is None:
            del params[-1]
        return '%s(%s)' % (type(self).__name__, ', '.join(repr(x) for x in params))

    @property
    def uri_domain(self):
        return protocol.URI(host=self.domain, port=self.port, use_tls=self.use_tls)

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
    MSRPSessionClass = MSRPSession
    SRVConnectorClass = None

    def __init__(self, *args, **kwargs):
        self.args = args
        self.kwargs = kwargs
        if 'MSRPSessionClass' in kwargs:
            self.MSRPSessionClass = self.kwargs.pop('MSRPSessionClass')

    def generate_local_uri(self, port=0):
        return protocol.URI(host=default_host_ip, port=port, session_id=random_string(12))

    def _connect(self, local_uri, remote_uri):
        from twisted.internet import reactor
        creator = GreenClientCreator(reactor, self.MSRPSessionClass, local_uri, *self.args, **self.kwargs)
        if remote_uri.use_tls:
            from gnutls.interfaces.twisted import X509Credentials
            cred = X509Credentials(None, None)
            connectFuncName = 'connectTLS'
            connectFuncArgs = (cred, )
            service = 'msrps'
        else:
            connectFuncName = 'connectTCP'
            connectFuncArgs = ()
            service = 'msrp'
        if remote_uri.host:
            args = (remote_uri.host, remote_uri.port or 2855) + connectFuncArgs
            msrp = getattr(creator, connectFuncName)(*args)
        else:
            if not remote_uri.domain:
                raise ValueError("remote_uri must have either 'host' or 'domain'")
            msrp = creator.connectSRV(service, remote_uri.domain,
                                      connectFuncName=connectFuncName,
                                      connectFuncArgs=connectFuncArgs,
                                      ConnectorClass=self.SRVConnectorClass)
        return msrp

class ConnectorDirect(ConnectBase):

    BOGUS_LOCAL_PORT = 12345

    def prepare(self, local_uri=None):
        if local_uri is None:
            local_uri = self.generate_local_uri(self.BOGUS_LOCAL_PORT)
        self.local_uri = local_uri
        return [self.local_uri]

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
        factory = SpawnFactory(handler, self.MSRPSessionClass, local_uri, *self.args, **self.kwargs)
        if local_uri.use_tls is False:
            port = reactor.listenTCP(local_uri.port or 0, factory)
        else:
            from gnutls.interfaces.twisted import X509Credentials
            cred = X509Credentials(None, None)
            port = reactor.listenTLS(local_uri.port or 0, factory, cred)
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
        return [local_uri]

    def _accept(self):
        return self.transport_event.wait()

    def complete(self, full_remote_path):
        """Accept an incoming MSRP connection and bind it.
        Return MSRPSession instance.
        """
        try:
            with MSRPIncomingConnectTimeout.timeout():
                msrp = self._accept()
        finally:
            self.listener.stopListening()
            del self.listener
            del self.transport_event
        with MSRPBindSessionTimeout.timeout():
            msrp.accept_binding(full_remote_path)
        return msrp

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

class ConnectorRelay(RelayConnectBase):

    def prepare(self, local_uri=None):
        if local_uri is None:
            local_uri = self.generate_local_uri()
        self.msrp = self._relay_connect_timeout(local_uri)
        return self.msrp.full_local_path

    def complete(self, full_remote_path):
        try:
            with MSRPBindSessionTimeout.timeout():
                self.msrp.bind(full_remote_path)
            return self.msrp
        finally:
            del self.msrp

class AcceptorRelay(RelayConnectBase):

    def prepare(self, local_uri=None):
        if local_uri is None:
            local_uri = self.generate_local_uri()
        self.msrp = self._relay_connect_timeout(local_uri)
        return self.msrp.full_local_path

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

