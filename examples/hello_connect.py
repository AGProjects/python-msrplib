# Copyright (C) 2008-2009 AG Projects. See LICENSE for details.
#

import sys
from eventlib import proc
from msrplib.connect import ConnectorDirect
from msrplib.protocol import URI
from msrplib.trafficlog import Logger
from msrplib.session import GreenMSRPSession

from twisted.internet import reactor # let eventlib know we want twisted-based hub

local_uri = URI(session_id='client', use_tls=False)
remote_uri = URI(session_id='server', use_tls=False)
connector = ConnectorDirect(logger=Logger())
connector.prepare(local_uri)
transport = connector.complete([remote_uri])
session = GreenMSRPSession(transport)

session.send_message('hi', 'text/plain')
print 'received: %s' % session.receive_chunk().data
session.shutdown()
