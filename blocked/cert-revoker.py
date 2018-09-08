#!/usr/bin/env python
"""
cert-revoker.py

This script allows users to revoke a given certificate.
"""
import argparse
import base64
import hashlib
import json
from urllib import error, request

import cbor
import Crypto
import pyDes
from Crypto import Random
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from sawtooth_sdk.protobuf.batch_pb2 import Batch, BatchHeader, BatchList
from sawtooth_sdk.protobuf.transaction_pb2 import (Transaction,
                                                   TransactionHeader)
from sawtooth_signing import CryptoFactory, create_context, secp256k1

from addressing import addresser
import utils


class CertificateRevoker():

    def __init__(self, certificate, dsa, rsa):
        # We need this to generate the DSA-related information.
        self._context = create_context('secp256k1')
        self._crypto_factory = CryptoFactory(self._context)

        # DSA
        self._dsa_private = secp256k1.Secp256k1PrivateKey.from_hex(dsa)
        self._dsa_public = secp256k1.Secp256k1PublicKey(
            self._dsa_private.secp256k1_private_key.pubkey
        )
        self._transaction_signer = self._crypto_factory.new_signer(self._dsa_private)

        # RSA
        with open(rsa, 'r') as f:
            self._rsa = RSA.importKey(f.read())

        # Certificate Data
        self._certificate_identifier = certificate

    def _make_payload(self, certificate, symmetric_key):
        payload = {}

        certificate['active'] = False

        encrypted_certificate = utils.des_encrypt(certificate, symmetric_key)

        payload['op'] = 'revoke'
        payload['data'] = {}
        payload['data']['id'] = self._certificate_identifier
        payload['data']['certificate'] = encrypted_certificate.decode()

        return payload

    def main(self):
        print('Generating Addresses...', end='', flush=True)
        certificate_address = addresser.make_certificate_address(
            self._certificate_identifier.encode()
        )
        print('[OK]')

        raw_data = utils.fetch_state(certificate_address)

        if raw_data:
            encoded_data = json.loads(raw_data)
            data = cbor.loads(base64.b64decode(encoded_data['data']))
            symmetric_key = utils.decrypt_symmetric_key(data['permissions'], self._rsa)

            certificate = json.loads(utils.des_decrypt(data['certificate'], symmetric_key))

            print('Generating Payload...', end='', flush=True)
            # Create and encode the payload.
            payload = self._make_payload(certificate, symmetric_key)
            encoded_payload = cbor.dumps(payload)
            print('[OK]')

            # Create Transaction.
            transaction = utils.make_transaction(
                encoded_payload,
                self._transaction_signer,
                [certificate_address],
                [certificate_address]
            )

            # Create Batch.
            batch = utils.make_batch(transaction, self._transaction_signer)
            batch_list = BatchList(batches=[batch]).SerializeToString()

            # Submit new Batch.
            link = utils.submit_batch(batch_list)

            print('Status:')
            print(link)
        else:
            print('error: could not find certificate')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--certificate', help="identifier of certificate", required=True)
    parser.add_argument('--secret-dsa', help='secret DSA key to validate identity', required=True)
    parser.add_argument('--secret-rsa', help='secret RSA key to decrypt the data', required=True)
    args = parser.parse_args()

    issuer = CertificateRevoker(args.certificate, args.secret_dsa, args.secret_rsa)
    issuer.main()
