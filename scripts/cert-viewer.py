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

    def __init__(self, certificate):
        self._certificate = certificate

    def main(self):
        address = addresser._make_certificate_address(self._certificate.encode())

        try:
            req = request.Request(
                'http://localhost:8008/state/{}'.format(address),
                method='GET',
                headers={'Content-Type': 'application/octet-stream'}
            )
            resp = request.urlopen(req)
        except error.HTTPError as e:
            resp = e.file

        raw_data = resp.read()
        if raw_data:
            encoded_data = json.loads(raw_data)
            data = cbor.loads(base64.b64decode(encoded_data['data']))

            print(json.dumps(data, indent=4))
        else:
            print('error: could not find certificate')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--certificate', required=True)
    args = parser.parse_args()

    viewer = CertificateViewer(args.certificate)
    viewer.main()
