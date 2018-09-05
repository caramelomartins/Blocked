#!/usr/bin/env python

from distutils.core import setup

setup(
    name='blocked',
    version='0.1',
    description='Python implementation of an Access Control application, for Educational Certificates, based on a blockchain.',
    author='Hugo Martins',
    author_email='caramelo.martins@gmail.com',
    packages=['blocked', 'addressing', 'processor'],
)
