#!/usr/bin/env python
"""
cert-viewer.py

Views the contents of a given certificate.
"""
import argparse
import ast
import base64
import json
from urllib import error, request

import cbor
import Crypto
import pyDes
from Crypto import Random
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from sawtooth_signing import CryptoFactory, create_context, secp256k1

from processor import addresser


class CertificateViewer():

    def __init__(self, certificate, viewer, secret):
        self._certificate = certificate
        self._viewer = viewer
        self._secret = secret

        self._private = secp256k1.Secp256k1PrivateKey.from_hex(secret)
        self._public = secp256k1.Secp256k1PublicKey.from_hex(viewer)

        self._recipient_rsa = RSA.importKey(open('keys/recipient.keys/rsa/recipient', 'r').read())
        self._recipient_rsa_public = self._recipient_rsa.publickey()
        self._recruiter_rsa = RSA.importKey(open('keys/recruiter.keys/rsa/recruiter', 'r').read())
        self._recruiter_rsa_public = self._recruiter_rsa.publickey()

    def main(self):
        address = addresser.make_certificate_address(self._certificate.encode())

        print('Fetching Data...', end='', flush=True)
        try:
            req = request.Request(
                'http://localhost:8008/state/{}'.format(address),
                method='GET',
                headers={'Content-Type': 'application/octet-stream'}
            )
            resp = request.urlopen(req)
        except error.HTTPError as e:
            print('[Error]')
            resp = e.file
            exit()

        print('[OK]')

        raw_data = resp.read()

        if raw_data:
            encoded_data = json.loads(raw_data)
            data = cbor.loads(base64.b64decode(encoded_data['data']))
            symmetric_key = self._decrypt_symmetric_key(data['permissions'])

            certificate = json.loads(self._decrypt_certificate(symmetric_key, data))

            print()
            print('ID:', data['id'])
            print('Issuer:', certificate['issuer'])
            print('Recipient:', certificate['recipient'])
            print('Issued @', certificate['issued_at'])
            print('Status:', 'Active' if certificate['active'] else 'Revoked')
            print()
        else:
            print('error: could not find certificate')

    def _decrypt_certificate(self, symmetric_key, data):
        k = pyDes.des(
            symmetric_key,
            pyDes.CBC,
            b"\0\0\0\0\0\0\0\0",
            pad=None,
            padmode=pyDes.PAD_PKCS5
        )

        certificate = k.decrypt(base64.b64decode(data['certificate'])).decode()
        return certificate

    def _decrypt_symmetric_key(self, permissions):
        symmetric_key = None

        for i, p in enumerate(permissions):
            try:
                print('Attempt {}...'.format(i + 1), end='', flush=True)
                symmetric_key = PKCS1_OAEP.new(self._recruiter_rsa).decrypt(
                    base64.b64decode(p[list(p.keys())[0]].encode()))
                print('[OK]')
                break
            except ValueError:
                print('[Error]')

        if not symmetric_key:
            print('error: you do not have permission to access this certificate')
            exit()
        return base64.b64decode(symmetric_key)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--certificate', help="identifier of certificate", required=True)
    parser.add_argument('--viewer', help='key identifier', required=True)
    parser.add_argument('--secret', help='secret key to validate identity', required=True)
    args = parser.parse_args()

    viewer = CertificateViewer(args.certificate, args.viewer, args.secret)
    viewer.main()
