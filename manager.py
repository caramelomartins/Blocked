#!/usr/bin/env python
"""
manager.py

This script allows users to manage access control policies for the system.
"""
import argparse
import hashlib
from urllib import error, request

import cbor
from sawtooth_sdk.protobuf.batch_pb2 import Batch, BatchHeader, BatchList
from sawtooth_sdk.protobuf.transaction_pb2 import (Transaction,
                                                   TransactionHeader)
from sawtooth_signing import CryptoFactory, create_context, secp256k1

from processor import addresser


class PermissionsManager():
    def __init__(self, certificate, subject, secret, remove):
        self._context = create_context('secp256k1')
        self._private_key = secp256k1.Secp256k1PrivateKey.from_hex(secret)
        self._subject = secp256k1.Secp256k1PublicKey.from_hex(subject)
        self._transaction_signer = CryptoFactory(self._context).new_signer(self._private_key)
        self._certificate = certificate
        self._remove = remove

    def _generate_batch_list(self, key):
        payload = self._make_payload()
        address = addresser.make_certificate_address(self._certificate.encode())
        transaction = self._make_transaction(address, key, cbor.dumps(payload))
        batch = self._make_batch(transaction)

        batch_list = BatchList(batches=[batch]).SerializeToString()
        return batch_list

    def _make_batch(self, txn):
        print('Creating Batch...', end='', flush=True)
        transactions = [txn]

        batch_header = BatchHeader(
            signer_public_key=self._transaction_signer.get_public_key().as_hex(),
            transaction_ids=[txn.header_signature for txn in transactions],
        ).SerializeToString()

        signature = self._transaction_signer.sign(batch_header)

        batch = Batch(
            header=batch_header,
            header_signature=signature,
            transactions=transactions
        )
        print('[OK]')

        return batch

    def _make_transaction(self, address, key, payload):
        print('Creating Transaction...', end='', flush=True)
        header = TransactionHeader(
            family_name=addresser.FAMILY_NAME,
            family_version=addresser.FAMILY_VERSION,
            inputs=[address],
            outputs=[address],
            signer_public_key=key,
            batcher_public_key=key,
            dependencies=[],
            payload_sha512=hashlib.sha512(payload).hexdigest()
        ).SerializeToString()

        signature = self._transaction_signer.sign(header)

        transaction = Transaction(
            header=header,
            header_signature=signature,
            payload=payload
        )
        print('[OK]')

        return transaction

    def _make_payload(self):
        payload = {}

        if self._remove:
            payload['op'] = 'revoke_access'
        else:
            payload['op'] = 'grant_access'

        payload['data'] = {}
        payload['data']['id'] = self._certificate
        payload['data']['subject'] = self._subject.as_hex()

        return payload

    def main(self):
        signer_public_key = self._transaction_signer.get_public_key().as_hex()
        batch_list = self._generate_batch_list(signer_public_key)

        print('Submitting Request...', end='', flush=True)
        try:
            req = request.Request(
                'http://localhost:8008/batches',
                batch_list,
                method='POST',
                headers={'Content-Type': 'application/octet-stream'}
            )
            resp = request.urlopen(req)
        except error.HTTPError as e:
            print('[Error]')
            resp = e.file
        print('[OK]')

        print("Addresses:")
        print(resp.read().decode())


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--certificate', help="identifier of certificate", required=True)
    parser.add_argument('--subject', help='subject identifier', required=True)
    parser.add_argument('--secret', help='subject that is performing management', required=True)
    parser.add_argument('-r', '--remove', help='remove existing permissions', action='store_true')
    args = parser.parse_args()

    manager = PermissionsManager(args.certificate, args.subject, args.secret, args.remove)
    manager.main()
