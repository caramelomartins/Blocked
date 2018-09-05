#!/usr/bin/env python
"""
cert-issuer.py

Issue a certificate from a given Institution to a given Student.
"""
import argparse
import base64
import datetime
import hashlib
import os
import uuid

import cbor
import Crypto
from Crypto import Random
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from sawtooth_sdk.protobuf.batch_pb2 import Batch, BatchHeader, BatchList
from sawtooth_signing import CryptoFactory, create_context, secp256k1

from addressing import addresser
import utils


class CertificateIssuer():

    def __init__(self, recipient, secret, recipient_rsa, issuer_rsa):
        # We need this to generate the DSA-related information.
        self._context = create_context('secp256k1')
        self._crypto_factory = CryptoFactory(self._context)

        # DSA
        self._issuer_dsa_private = secp256k1.Secp256k1PrivateKey.from_hex(secret)
        self._transaction_signer = self._crypto_factory.new_signer(self._issuer_dsa_private)
        self._issuer_dsa_public = self._transaction_signer.get_public_key()

        self._recipient_dsa_public = secp256k1.Secp256k1PublicKey.from_hex(recipient)

        # RSA
        with open(issuer_rsa, 'r') as f:
            self._issuer_rsa = RSA.importKey(f.read())

        with open(recipient_rsa, 'r') as f:
            self._recipient_rsa = RSA.importKey(f.read())

        # DES
        # Here we generate a random hash and we slice it for the first 8 bytes which
        # is what DES accepts.
        self._symmetric_key = hashlib.sha256(os.urandom(128)).hexdigest()[:8].encode()

        # Certificate Data
        self._certificate_identifier = str(uuid.uuid4())

    def _make_payload(self):
        # Define Certificate
        issuer = self._issuer_dsa_public.as_hex()
        recipient = self._recipient_dsa_public.as_hex()

        certificate = {
            'issuer': issuer,
            'recipient': recipient,
            'issued_at': str(datetime.datetime.now()),
            'active': True
        }

        # Encrypt Data and Symmetric Key
        encrypted_certificate = utils.des_encrypt(certificate, self._symmetric_key)
        encoded_symmetric_key = base64.b64encode(self._symmetric_key)

        payload = {}

        payload['op'] = 'issue'
        payload['data'] = {}
        payload['data']['id'] = self._certificate_identifier
        payload['data']['certificate'] = encrypted_certificate.decode()
        payload['data']['owners'] = [issuer, recipient]

        # Encrypt Symmetric Key for initial permissions of Issuer and Recipient.

        issuer_pkcs1 = PKCS1_OAEP.new(self._issuer_rsa)
        recipient_pkcs1 = PKCS1_OAEP.new(self._recipient_rsa)

        encrypted_issuer_key = issuer_pkcs1.encrypt(encoded_symmetric_key)
        encrypted_recipient_key = recipient_pkcs1.encrypt(encoded_symmetric_key)

        encoded_issuer_key = base64.b64encode(encrypted_issuer_key)
        encoded_recipient_key = base64.b64encode(encrypted_recipient_key)

        payload['data']['permissions'] = [
            {issuer: encoded_issuer_key.decode()},
            {recipient: encoded_recipient_key.decode()}
        ]

        return payload

    def main(self):
        signer_public_key = self._issuer_dsa_public.as_hex()

        print('Generating Addresses...', end='', flush=True)
        # Generate an Address for the new Certificate.
        certificate_address = addresser.make_certificate_address(
            self._certificate_identifier.encode()
        )

        issuer_address = addresser.make_certificate_address(
            self._issuer_dsa_public.as_hex().encode()
        )

        recipient_address = addresser.make_certificate_address(
            self._recipient_dsa_public.as_hex().encode()
        )
        print('[OK]')

        print('Generating Payload...', end='', flush=True)
        # Create and encode the payload.
        payload = self._make_payload()
        encoded_payload = cbor.dumps(payload)
        print('[OK]')

        # Create Transaction.
        transaction = utils.make_transaction(
            encoded_payload,
            self._transaction_signer,
            [certificate_address, issuer_address, recipient_address],
            [certificate_address, issuer_address, recipient_address]
        )

        # Create Batch.
        batch = utils.make_batch(transaction, self._transaction_signer)
        batch_list = BatchList(batches=[batch]).SerializeToString()

        # Submit new Batch.
        link = utils.submit_batch(batch_list)

        print('identifier:', self._certificate_identifier)
        print('Status:')
        print(link)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--recipient', help="Recipient's DSA Public Key'", required=True)
    parser.add_argument('--secret', help="Issuer's DSA Private Key", required=True)
    parser.add_argument('--recipient-rsa', help="Path to Recipient's RSA Public Key", required=True)
    parser.add_argument('--issuer-rsa', help="Path to Issuer's RSA Public Key", required=True)
    args = parser.parse_args()

    issuer = CertificateIssuer(args.recipient, args.secret, args.recipient_rsa, args.issuer_rsa)
    issuer.main()
