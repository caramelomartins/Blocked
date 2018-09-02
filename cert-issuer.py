#!/usr/bin/env python
"""
cert-issuer.py

Issue a certificate from a given Institution to a given Student.
"""
import argparse
import datetime
import hashlib
import uuid
from urllib import error, request

import cbor
from sawtooth_sdk.protobuf.batch_pb2 import Batch, BatchHeader, BatchList
from sawtooth_sdk.protobuf.transaction_pb2 import (Transaction,
                                                   TransactionHeader)
from sawtooth_signing import CryptoFactory, create_context, secp256k1

from processor import addresser


class CertificateIssuer():

    def __init__(self, issuer, recipient, secret):
        self._context = create_context('secp256k1')
        self._private_key = secp256k1.Secp256k1PrivateKey.from_hex(secret)
        self._transaction_signer = CryptoFactory(self._context).new_signer(self._private_key)
        self._recipient = secp256k1.Secp256k1PublicKey.from_hex(recipient)
        self._issuer = issuer

        self._identifier = uuid.uuid4().hex

    def _generate_batch(self, issuer, recipient):
        payload = self._make_payload(issuer, recipient)
        address = addresser.make_certificate_address(self._identifier.encode())
        transaction = self._make_transaction(address, issuer, cbor.dumps(payload))
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

    def _make_transaction(self, address, issuer, payload):
        print('Creating Transaction...', end='', flush=True)
        header = TransactionHeader(
            family_name=addresser.FAMILY_NAME,
            family_version=addresser.FAMILY_VERSION,
            inputs=[address],
            outputs=[address],
            signer_public_key=issuer,
            batcher_public_key=issuer,
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

    def _make_payload(self, issuer, recipient):
        payload = {}

        payload['op'] = 'issue'
        payload['data'] = {}
        payload['data']['id'] = self._identifier
        payload['data']['issuer'] = issuer
        payload['data']['recipient'] = recipient
        payload['data']['issuer_at'] = str(datetime.datetime.now())
        payload['data']['active'] = True
        payload['data']['permissions'] = [self._issuer, self._recipient.as_hex()]

        return payload

    def main(self):
        signer_public_key = self._transaction_signer.get_public_key().as_hex()

        if signer_public_key != self._issuer:
            raise Exception('your identity does not match')

        batch_list = self._generate_batch(
            signer_public_key,
            self._recipient.as_hex(),
        )

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
            resp = e.file
        print('[OK]')

        print('identifier:', self._identifier)
        print('Addresses:')
        print(resp.read().decode())


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--issuer', help="issuer of certificate", required=True)
    parser.add_argument('--recipient', help="recipient of certificate", required=True)
    parser.add_argument('--secret', help='secret key to validate identity', required=True)
    args = parser.parse_args()

    issuer = CertificateIssuer(args.issuer, args.recipient, args.secret)
    issuer.main()
