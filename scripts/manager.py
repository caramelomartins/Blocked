#!/usr/bin/env python
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
    def __init__(self, key, subject, certificate, revoke):
        context = create_context('secp256k1')
        private_key = self._extract_private_key_from_file(key)
        subject_pkey = self._extract_public_key_from_file(subject)

        self._subject = subject_pkey
        self._transaction_signer = CryptoFactory(context).new_signer(private_key)
        self._certificate = certificate
        self._revoke = revoke

    def _extract_private_key_from_file(self, source):
        with open(source, 'r') as file:
            data = file.readlines()[0]

        return secp256k1.Secp256k1PrivateKey.from_hex(data)

    def _extract_public_key_from_file(self, source):
        with open(source, 'r') as file:
            data = file.readlines()[0]

        return secp256k1.Secp256k1PublicKey.from_hex(data)

    def _generate_batch(self, key):
        payload = self._make_payload()
        address = addresser._make_certificate_address(self._certificate.encode())
        transaction = self._make_transaction(address, key, cbor.dumps(payload))
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

    def _make_transaction(self, address, key, payload):

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
        return transaction

    def _make_payload(self):
        payload = {}

        if self._revoke:
            payload['op'] = 'revoke_access'
        else:
            payload['op'] = 'grant_access'

        payload['data'] = {}
        payload['data']['id'] = self._certificate
        payload['data']['subject'] = self._subject.as_hex()

        return payload

    def main(self):
        signer_public_key = self._transaction_signer.get_public_key().as_hex()
        batch_list = self._generate_batch(signer_public_key)

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

        print(resp.read().decode())


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--subject', required=True)
    parser.add_argument('--key', required=True)
    parser.add_argument('--certificate', required=True)
    parser.add_argument('--revoke', action='store_true')
    args = parser.parse_args()

    manager = PermissionsManager(args.key, args.subject, args.certificate, args.revoke)
    manager.main()
