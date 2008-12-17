#!/usr/bin/env python

from distutils.core import setup
from msrplib import __version__

setup(name         = "python-msrplib",
      version      = __version__,
      author       = "Denis Bilenko",
      author_email = "support@ag-projects.com",
      license      = "LGPL",
      description  = "Client library for MSRP protocol and its relay extension (RFC 4975 and RFC4976)",
      url          = "http://msrprelay.org",
      packages = ['msrplib'])

