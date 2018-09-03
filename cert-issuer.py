#!/usr/bin/env python
"""
cert-issuer.py

Issue a certificate from a given Institution to a given Student.
"""
import argparse
import base64
import datetime
import hashlib
import json
import uuid
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

from processor import addresser


class CertificateIssuer():

    def __init__(self, issuer, recipient, secret):
        self._context = create_context('secp256k1')
        self._private_key = secp256k1.Secp256k1PrivateKey.from_hex(secret)
        self._transaction_signer = CryptoFactory(self._context).new_signer(self._private_key)
        self._recipient = secp256k1.Secp256k1PublicKey.from_hex(recipient)
        self._issuer = issuer
        self._symmetric_key = b'weirdkey'
        self._identifier = uuid.uuid4().hex

        self._issuer_rsa = RSA.importKey(open('keys/issuer.keys/rsa/issuer', 'r').read())
        self._issuer_rsa_public = self._issuer_rsa.publickey()
        self._recipient_rsa = RSA.importKey(open('keys/recipient.keys/rsa/recipient', 'r').read())
        self._recipient_rsa_public = self._recipient_rsa.publickey()

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
            inputs=[address, addresser.make_certificate_address(
                self._issuer.encode()), addresser.make_certificate_address(self._recipient.as_hex().encode())],
            outputs=[address, addresser.make_certificate_address(
                self._issuer.encode()), addresser.make_certificate_address(self._recipient.as_hex().encode())],
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

        certificate = {
            'issuer': issuer,
            'recipient': recipient,
            'issued_at': str(datetime.datetime.now()),
            'active': True
        }

        encrypted_certificate = self._encrypt(certificate)
        encoded_symmetric_key = base64.b64encode(self._symmetric_key)

        payload = {}

        payload['op'] = 'issue'
        payload['data'] = {}
        payload['data']['id'] = self._identifier
        payload['data']['certificate'] = encrypted_certificate.decode()
        payload['data']['owners'] = [
            self._issuer,
            self._recipient.as_hex()
        ]
        payload['data']['permissions'] = [
            {
                self._issuer: base64.b64encode(PKCS1_OAEP.new(self._issuer_rsa).encrypt(
                    encoded_symmetric_key)).decode()
            },
            {
                self._recipient.as_hex(): base64.b64encode(PKCS1_OAEP.new(self._recipient_rsa).encrypt(
                    encoded_symmetric_key)).decode()
            }
        ]

        print(payload)

        return payload

    def _encrypt(self, data):
        k = pyDes.des(
            self._symmetric_key,
            pyDes.CBC,
            b"\0\0\0\0\0\0\0\0",
            pad=None,
            padmode=pyDes.PAD_PKCS5
        )
        d = k.encrypt(json.dumps(data).encode('utf-8'))
        assert k.decrypt(d) == json.dumps(data).encode('utf-8')

        return base64.b64encode(d)

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
