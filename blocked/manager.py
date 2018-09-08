#!/usr/bin/env python
"""
manager.py

This script allows users to manage access control policies for the system.
"""
import argparse
import base64
import json

import cbor
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from sawtooth_sdk.protobuf.batch_pb2 import BatchList
from sawtooth_signing import CryptoFactory, create_context, secp256k1

from addressing import addresser
import utils


class PermissionsManager():
    def __init__(self, certificate, owner_dsa, owner_rsa, subject_dsa, subject_rsa, remove):
        # We need this to generate the DSA-related information.
        self._context = create_context('secp256k1')
        self._crypto_factory = CryptoFactory(self._context)

        # DSA
        self._recruiter_dsa_private = secp256k1.Secp256k1PrivateKey.from_hex(owner_dsa)
        self._recruiter_dsa_public = secp256k1.Secp256k1PublicKey(
            self._recruiter_dsa_private.secp256k1_private_key.pubkey
        )
        self._subject_dsa_public = secp256k1.Secp256k1PublicKey.from_hex(subject_dsa)
        self._transaction_signer = self._crypto_factory.new_signer(self._recruiter_dsa_private)

        # RSA
        with open(owner_rsa, 'r') as f:
            self._owner_rsa = RSA.importKey(f.read())

        with open(subject_rsa, 'r') as f:
            self._subject_rsa = RSA.importKey(f.read())

        # Certificate Data
        self._certificate_identifier = certificate
        self._remove = remove

    def _make_payload(self, symmetric_key):
        payload = {}

        encoded_symmetric_key = base64.b64encode(symmetric_key)

        if self._remove:
            payload['op'] = 'revoke_access'
        else:
            payload['op'] = 'grant_access'

        payload['data'] = {}
        payload['data']['id'] = self._certificate_identifier
        payload['data']['permissions'] = {
            'data': base64.b64encode(PKCS1_OAEP.new(self._subject_rsa).encrypt(encoded_symmetric_key)).decode(),
            'id': self._subject_dsa_public.as_hex()
        }

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

            # Decrypt to validate permissions.
            symmetric_key = utils.decrypt_symmetric_key(data['permissions'], self._owner_rsa)

            print('Generating Payload...', end='', flush=True)
            # Create and encode the payload.
            payload = self._make_payload(symmetric_key)
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
    parser.add_argument('--subject-dsa', help='subject DSA identifier', required=True)
    parser.add_argument('--subject-rsa', help='subject RSA identifier', required=True)
    parser.add_argument('--secret-dsa', help='owner that is performing management', required=True)
    parser.add_argument('--secret-rsa', help='secret RSA key to decrypt the data', required=True)
    parser.add_argument('-r', '--remove', help='remove existing permissions', action='store_true')
    args = parser.parse_args()

    manager = PermissionsManager(
        args.certificate, args.secret_dsa, args.secret_rsa, args.subject_dsa, args.subject_rsa, args.remove
    )
    manager.main()
