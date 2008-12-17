#!/usr/bin/env python

from distutils.core import setup
from msrplib import __version__

setup(name         = "python-msrplib",
      version      = __version__,
      author       = "Denis Bilenko",
      author_email = "support@ag-projects.com",
      url          = "http://pypjua.org",
      packages = ['msrplib'])

