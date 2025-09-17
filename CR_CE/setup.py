#!/usr/bin/env python
from pkgutil import walk_packages
from setuptools import setup

import ghost_cr_ce


def find_packages(path, prefix):
    yield prefix
    prefix = prefix + "."
    for _, name, ispkg in walk_packages(path, prefix):
        if ispkg:
            yield name

setup(name='ghost-cr-ce',
      version="0.10",
      author='Ioan Cosmin Szanto',
      author_email='cosmin.szanto@kalosis.com',
      url='https://www.kalosis.com',
      platforms=['any'],
      packages=list(find_packages(ghost_cr_ce.__path__, ghost_cr_ce.__name__)))
