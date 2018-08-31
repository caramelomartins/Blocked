#!/usr/bin/env python
"""
cert-viewer.py

Views the contents of a given certificate.
"""
import argparse
import base64
import json
from urllib import error, request

import cbor
from sawtooth_signing import CryptoFactory, create_context, secp256k1

from processor import addresser


class CertificateViewer():

    def __init__(self, certificate, viewer, secret):
        self._certificate = certificate
        self._viewer = viewer
        self._secret = secret

        self._private = secp256k1.Secp256k1PrivateKey.from_hex(secret)
        self._public = secp256k1.Secp256k1PublicKey.from_hex(viewer)

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
        print('[OK]')

        raw_data = resp.read()

        if raw_data:
            encoded_data = json.loads(raw_data)
            data = cbor.loads(base64.b64decode(encoded_data['data']))

            if self._public in data['permissions']:
                print(json.dumps(data, indent=4))
            else:
                print('error: you do not have permissions to view this certificate')
        else:
            print('error: could not find certificate')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--certificate', help="identifier of certificate", required=True)
    parser.add_argument('--viewer', help='key identifier', required=True)
    parser.add_argument('--secret', help='secret key to validate identity', required=True)
    args = parser.parse_args()

    viewer = CertificateViewer(args.certificate, args.viewer, args.secret)
    viewer.main()
