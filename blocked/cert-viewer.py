#!/usr/bin/env python
"""
cert-viewer.py

Views the contents of a given certificate.
"""
import argparse
import base64
import json

import cbor
from Crypto.PublicKey import RSA
from sawtooth_signing import secp256k1

import utils
from addressing import addresser


class CertificateViewer():

    def __init__(self, certificate, dsa, rsa):
        # Certificate
        self._certificate_identifier = certificate

        # DSA
        self._dsa_private = secp256k1.Secp256k1PrivateKey.from_hex(dsa)
        self._dsa_public = secp256k1.Secp256k1PublicKey(
            self._dsa_private.secp256k1_private_key.pubkey
        )

        # RSA
        with open(rsa, 'r') as f:
            self._rsa = RSA.importKey(f.read())

    def main(self):
        print('Generating Addresses...', end='', flush=True)
        certificate_address = addresser.make_certificate_address(
            self._certificate_identifier.encode()
        )
        print('[OK]')

        print('Fetching State...', end='', flush=True)
        raw_data = utils.fetch_state(certificate_address)
        print('[OK]')

        if raw_data:
            encoded_data = json.loads(raw_data)
            data = cbor.loads(base64.b64decode(encoded_data['data']))
            symmetric_key = utils.decrypt_symmetric_key(data['permissions'], self._rsa)

            certificate = json.loads(
                utils.des_decrypt(data['certificate'], symmetric_key)
            )

            print()
            print('ID:', data['id'])
            print('Issuer:', certificate['issuer'])
            print('Recipient:', certificate['recipient'])
            print('Issued @', certificate['issued_at'])
            print('Status:', 'Active' if certificate['active'] else 'Revoked')
            print()
        else:
            print('error: could not find certificate')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--certificate', help="identifier of certificate", required=True)
    parser.add_argument('--secret-dsa', help='secret DSA key to validate identity', required=True)
    parser.add_argument('--secret-rsa', help='secret RSA key to decrypt the data', required=True)
    args = parser.parse_args()

    viewer = CertificateViewer(args.certificate, args.secret_dsa, args.secret_rsa)
    viewer.main()
