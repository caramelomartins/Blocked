import argparse
import datetime
import json
import urllib.request
from hashlib import sha256, sha512
from urllib.error import HTTPError

import cbor
from sawtooth_sdk.protobuf.batch_pb2 import Batch, BatchHeader, BatchList
from sawtooth_sdk.protobuf.transaction_pb2 import (Transaction,
                                                   TransactionHeader)
from sawtooth_signing import CryptoFactory, create_context, secp256k1

from processor import addresser


class CertificateIssuer():

    def __init__(self, skey, recipient):
        context = create_context('secp256k1')
        private_key = self._extract_private_key(skey)
        recipient_pkey = self._extract_public_key(recipient)

        self._transaction_signer = CryptoFactory(context).new_signer(private_key)
        self._recipient = recipient_pkey

    def _extract_private_key(self, skey):
        file = open(skey, 'r')
        data = file.readlines()[0]

        private_key = secp256k1.Secp256k1PrivateKey.from_hex(data)
        return private_key

    def _extract_public_key(self, recipient):
        file = open(recipient, 'r')
        data = file.readlines()[0]

        public_key = secp256k1.Secp256k1PublicKey.from_hex(data)
        return public_key

    def _generate_batch(self, issuer, recipient):
        payload = {
            'op': 'issue',
            'data': {
                'issuer': issuer,
                'recipient': recipient,
                'issuer_at': str(datetime.datetime.now()),
                'content': ''
            }
        }

        payload_bytes = cbor.dumps(payload)

        address = addresser._make_certificate_address(issuer.encode(), recipient.encode())

        txn_header_bytes = TransactionHeader(
            family_name=addresser.FAMILY_NAME,
            family_version=addresser.FAMILY_VERSION,
            inputs=[address],
            outputs=[address],
            signer_public_key=issuer,
            batcher_public_key=issuer,
            dependencies=[],
            payload_sha512=sha512(payload_bytes).hexdigest()
        ).SerializeToString()

        signature = self._transaction_signer.sign(txn_header_bytes)

        txn = Transaction(
            header=txn_header_bytes,
            header_signature=signature,
            payload=payload_bytes
        )

        txns = [txn]

        batch_header_bytes = BatchHeader(
            signer_public_key=self._transaction_signer.get_public_key().as_hex(),
            transaction_ids=[txn.header_signature for txn in txns],
        ).SerializeToString()

        signature = self._transaction_signer.sign(batch_header_bytes)

        batch = Batch(
            header=batch_header_bytes,
            header_signature=signature,
            transactions=txns
        )

        batch_list_bytes = BatchList(batches=[batch]).SerializeToString()
        return batch_list_bytes

    def main(self):
        signer_pkey = self._transaction_signer.get_public_key().as_hex()

        batch_list_bytes = self._generate_batch(signer_pkey, self._recipient.as_hex())

        try:
            request = urllib.request.Request(
                'http://localhost:8008/batches',
                batch_list_bytes,
                method='POST',
                headers={'Content-Type': 'application/octet-stream'}
            )
            response = urllib.request.urlopen(request)
            print(json.loads(response.read()))
        except HTTPError as e:
            response = e.file


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--skey', required=True)
    parser.add_argument('--recipient', required=True)
    args = parser.parse_args()

    issuer = CertificateIssuer(args.skey, args.recipient)
    issuer.main()
