#!/usr/bin/env python

from setuptools import setup
from pkgutil import walk_packages

import ghost_protocol

def find_packages(path, prefix):
    yield prefix
    prefix = prefix + "."
    for _, name, ispkg in walk_packages(path, prefix):
        if ispkg:
            yield name

setup(name='ghost-protocol',
      version="0.10",
      author='Ioan Cosmin Szanto',
      author_email='cosmin.szanto@kalosis.com',
      url='https://www.kalosis.com',
      platforms=['any'],
      setup_requires=['blist', 'zmq'],
      packages=list(find_packages(ghost_protocol.__path__, ghost_protocol.__name__)),
     )
