#!/usr/bin/env python
import argparse
import datetime
import hashlib
import json
import logging
import uuid
from urllib import error, request

import cbor
from sawtooth_sdk.protobuf.batch_pb2 import Batch, BatchHeader, BatchList
from sawtooth_sdk.protobuf.transaction_pb2 import (Transaction,
                                                   TransactionHeader)
from sawtooth_signing import CryptoFactory, create_context, secp256k1

from processor import addresser


class CertificateIssuer():

    def __init__(self, issuer, recipient, content):
        context = create_context('secp256k1')
        private_key = self._extract_private_key_from_file(issuer)
        recipient_pkey = self._extract_public_key_from_file(recipient)

        self._transaction_signer = CryptoFactory(context).new_signer(private_key)
        self._recipient = recipient_pkey
        self._content = content
        self._identifier = uuid.uuid4().hex

    def _extract_private_key_from_file(self, source):
        with open(source, 'r') as file:
            data = file.readlines()[0]

        return secp256k1.Secp256k1PrivateKey.from_hex(data)

    def _extract_public_key_from_file(self, source):
        with open(source, 'r') as file:
            data = file.readlines()[0]

        return secp256k1.Secp256k1PublicKey.from_hex(data)

    def _generate_batch(self, issuer, recipient, content):
        payload = self._make_payload(issuer, recipient, content)
        address = addresser._make_certificate_address(self._identifier.encode())
        transaction = self._make_transaction(address, issuer, cbor.dumps(payload))
        batch = self._make_batch(transaction)

        batch_list = BatchList(batches=[batch]).SerializeToString()
        return batch_list

    def _make_batch(self, txn):
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
        return batch

    def _make_transaction(self, address, issuer, payload):
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
        return transaction

    def _make_payload(self, issuer, recipient, content):
        payload = {}
        payload['op'] = 'issue'
        payload['data'] = {}
        payload['data']['id'] = self._identifier
        payload['data']['issuer'] = issuer
        payload['data']['recipient'] = recipient
        payload['data']['issuer_at'] = str(datetime.datetime.now())
        payload['data']['content'] = content
        payload['data']['active'] = True
        payload['data']['permissions'] = []

        return payload

    def main(self):
        signer_public_key = self._transaction_signer.get_public_key().as_hex()

        batch_list = self._generate_batch(
            signer_public_key,
            self._recipient.as_hex(),
            self._content
        )

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

        print('identifier:', self._identifier)
        print(resp.read().decode())


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--issuer', required=True)
    parser.add_argument('--recipient', required=True)
    parser.add_argument('--content', default=None)
    args = parser.parse_args()

    issuer = CertificateIssuer(args.issuer, args.recipient, args.content)
    issuer.main()
