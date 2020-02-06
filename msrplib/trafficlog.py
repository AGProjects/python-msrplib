# Copyright (C) 2008-2012 AG Projects. See LICENSE for details

import datetime

# noinspection PyPackageRequirements
from application import log


__all__ = 'Logger',


class Logger(log.ContextualLogger):
    logger = log.get_logger('msrplib')

    def __init__(self, prefix=None, log_traffic=False):
        super(Logger, self).__init__(logger=self.logger)
        self.prefix = prefix or ''
        self.log_traffic = log_traffic

    def apply_context(self, message):
        return '{}{}'.format(self.prefix, message) if message != '' else ''

    def received_chunk(self, data, transport):
        if self.log_traffic:
            address_line = '{local.host}:{local.port} <-- {remote.host}:{remote.port}'.format(local=transport.getHost(), remote=transport.getPeer())
            self.info('{} {}\n\n{}'.format(datetime.datetime.now(), address_line, data.chunk_header + data.data + data.chunk_footer))

    def sent_chunk(self, data, transport):
        if self.log_traffic:
            address_line = '{local.host}:{local.port} --> {remote.host}:{remote.port}'.format(local=transport.getHost(), remote=transport.getPeer())
            self.info('{} {}\n\n{}'.format(datetime.datetime.now(), address_line, data.encoded_header + data.data + data.encoded_footer))

    def received_illegal_data(self, data, transport):
        if self.log_traffic:
            address_line = '{local.host}:{local.port} <-- {remote.host}:{remote.port}'.format(local=transport.getHost(), remote=transport.getPeer())
            self.info('[Bad Message] {} {}\n\n{}'.format(datetime.datetime.now(), address_line, data))
