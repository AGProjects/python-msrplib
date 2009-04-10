#!/usr/bin/python
# Copyright (C) 2008-2009 AG Projects. See LICENSE for details.
#

"""Example file transfer with MSRPSession.

Run this script as a server in one window:

 ./filetransfer.py server /tmp/destination

Then open another console and run it as a client:

 ./filetransfer.py client /etc/passwd

The client will send the file you specified (/etc/passwd in this case)
to the server. The server will print info about the bits received and save
the file under the filename provided (/tmp/destination in this case).
During file transfer both will exchange messages over the same session,
demonstrating how an instant message enjoys a higher priority than file transfer.
"""

import sys
import os
from time import time
from twisted.internet.error import ConnectionDone
from eventlet import api, proc
from msrplib.connect import AcceptorDirect, ConnectorDirect
from msrplib.protocol import URI
from msrplib.trafficlog import Logger
from msrplib.session import MSRPSession, OutgoingFile

from twisted.internet import reactor # let eventlet know we want twisted-based hub

# from application import log
# log.level.current = log.level.DEBUG

from msrplib.trafficlog import hook_std_output; hook_std_output()

def main():
    if not sys.argv[1:] or sys.argv[1] not in ['client', 'server'] or sys.argv[3:]:
        sys.exit(__doc__)

    role = sys.argv[1]

    if sys.argv[2:]:
        filename = sys.argv[2]
    else:
        filename = None

    if role == 'client':
        local_uri = URI(session_id='client', use_tls=False)
        remote_uri = URI(session_id='server', use_tls=False)
        connector = ConnectorDirect(logger=Logger(is_enabled_func=lambda : False))
        dest = None
    else:
        local_uri = URI(session_id='server', use_tls=False)
        remote_uri = URI(session_id='client', use_tls=False)
        connector = AcceptorDirect(logger=Logger(is_enabled_func=lambda : False))
        if filename:
            if os.path.exists(filename) and os.path.isfile(filename):
                sys.exit('%s already exists. Remove it first or provide another destination' % filename)
            dest = file(filename, 'w+')

    connector.prepare(local_uri)
    transport = connector.complete([remote_uri])

    main_greenlet = api.getcurrent()

    def on_received(chunk=None, error=None):
        if chunk is not None:
            if chunk.content_type == 'text/plain':
                print '\nreceived message: %s' % chunk.data
            elif chunk.content_type == 'application/octet-stream':
                fro, to, total = chunk.byte_range
                dest.seek(fro-1)
                dest.write(chunk.data)
                if total:
                    percent = ' (%d%%)' % (100.0*(fro-1+len(chunk.data))/total)
                else:
                    percent = ''
                speed = (fro-1+len(chunk.data))/float((time()-start_time))/1024./1024
                print '\rwrote %s bytes to %s. %s bytes total%s %.2f MB/s       ' % (len(chunk.data), filename, fro-1+len(chunk.data), percent, speed),
                if chunk.contflag=='$':
                    api.spawn(api.kill, main_greenlet, proc.ProcExit)
        if error is not None:
            api.spawn(api.kill, main_greenlet, error.type, error.value, error.tb)

    session = MSRPSession(transport, on_incoming_cb=on_received)

    def sender():
        while True:
            session.send_message('hello from %s' % role, 'text/plain')
            api.sleep(3)

    sender = proc.spawn_link_exception(proc.wrap_errors(proc.ProcExit, sender))

    if filename and role=='client':
        if os.path.isfile(filename):
            size = os.stat(filename).st_size
        else:
            size = None
        f = file(filename)
        outgoing_file = OutgoingFile(f, size, 'application/octet-stream')
        print 'Sending %s %s bytes' % (filename, size)
        session.send_file(outgoing_file)
    start_time = time()

    try:
        api.get_hub().switch() # sleep forever
    except (proc.ProcExit, ConnectionDone):
        pass
    finally:
        sender.kill()
        session.shutdown()

if __name__=='__main__':
    main()
