# Copyright (C) 2008-2009 AG Projects. See LICENSE for details.
#

from msrplib.connect import DirectAcceptor
from msrplib.protocol import URI
from msrplib.trafficlog import Logger
from msrplib.session import GreenMSRPSession

from twisted.internet import reactor; del reactor  # let eventlib know we want twisted-based hub

logger = Logger()
local_uri = URI(session_id='server', use_tls=False)
remote_uri = URI(session_id='client', use_tls=False)
connector = DirectAcceptor(logger=logger)
connector.prepare(local_uri)
transport = connector.complete([remote_uri])
session = GreenMSRPSession(transport)

session.send_message('hello', 'text/plain')
logger.info('received: %s', session.receive_chunk().data)
session.shutdown()
