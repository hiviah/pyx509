#!/usr/bin/env python

#
# setup-ified it
#
from setuptools import setup, find_packages

setup(
    name = 'pyx509',
    version = '0.6', # Would really like to link this to a tag/branch/whatever
    install_requires = ['pyasn1 >= 0.1.4',],
    author = 'hiviah',
    author_email = 'hiviah@users.github.com',
    license = 'GPL',
    description = 'X.509 Certificate Parser for Python',
    url = 'https://github.com/hiviah/pyx509',
    classifiers = [
        '',
    ],
    packages = find_packages(),
)
