"""
addresser.py

This file contains functions and properties related to the addressing scheme and
namespace management for `blocked`.
"""
import hashlib

FAMILY_NAME = 'blocked'
FAMILY_VERSION = '0.1'
NAMESPACE = hashlib.sha512(FAMILY_NAME.encode('utf-8')).hexdigest()[:6]


def _make_certificate_address(identifier):
    return '{}{}'.format(
        NAMESPACE,
        hashlib.sha512(identifier).hexdigest()[:64]
    )
