#!/usr/bin/env python
"""
manager.py

This script allows users to manage access control policies for the system.
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

import addressing


class PermissionsManager():
    def __init__(self, certificate, subject, secret, remove):
        self._context = create_context('secp256k1')
        self._private_key = secp256k1.Secp256k1PrivateKey.from_hex(secret)
        self._subject = secp256k1.Secp256k1PublicKey.from_hex(subject)
        self._transaction_signer = CryptoFactory(self._context).new_signer(self._private_key)
        self._certificate = certificate
        self._remove = remove

        self._recruiter_rsa = RSA.importKey(open('keys/recruiter.keys/rsa/recruiter', 'r').read())
        self._recruiter_rsa_public = self._recruiter_rsa.publickey()
        self._recipient_rsa = RSA.importKey(open('keys/recipient.keys/rsa/recipient', 'r').read())
        self._recipient_rsa_public = self._recipient_rsa.publickey()

    def _generate_batch_list(self, key, symmetric_key):
        payload = self._make_payload(symmetric_key)
        address = addressing.addresser.make_certificate_address(self._certificate.encode())
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
            family_name=addressing.addresser.FAMILY_NAME,
            family_version=addressing.addresser.FAMILY_VERSION,
            inputs=[address, addressing.addresser.make_certificate_address(
                self._subject.as_hex().encode())],
            outputs=[address, addressing.addresser.make_certificate_address(
                self._subject.as_hex().encode())],
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

    def _make_payload(self, symmetric_key):
        payload = {}

        encoded_symmetric_key = base64.b64encode(symmetric_key)

        if self._remove:
            payload['op'] = 'revoke_access'
        else:
            payload['op'] = 'grant_access'

        payload['data'] = {}
        payload['data']['id'] = self._certificate
        payload['data']['permissions'] = {
            'data': base64.b64encode(PKCS1_OAEP.new(self._recruiter_rsa).encrypt(encoded_symmetric_key)).decode(),
            'id': self._subject.as_hex()
        }

        return payload

    def _decrypt_symmetric_key(self, permissions):
        symmetric_key = None

        for i, p in enumerate(permissions):
            try:
                print('Attempt {}...'.format(i + 1), end='', flush=True)
                symmetric_key = PKCS1_OAEP.new(self._recipient_rsa).decrypt(
                    base64.b64decode(p[list(p.keys())[0]].encode()))
                print('[OK]')
                break
            except ValueError:
                print('[Error]')

        if not symmetric_key:
            print('error: you do not have permission to access this certificate')
            exit()
        return base64.b64decode(symmetric_key)

    def main(self):
        address = addressing.addresser.make_certificate_address(self._certificate.encode())
        signer_public_key = self._transaction_signer.get_public_key().as_hex()

        print('Fetching Data...', end='', flush=True)
        try:
            req = request.Request(
                'http://localhost:8008/state/{}'.format(address),
                method='GET',
                headers={'Content-Type': 'application/octet-stream'}
            )
            resp = request.urlopen(req)
        except error.HTTPError as e:
            print('[Error]')
            resp = e.file
        print('[OK]')

        raw_data = resp.read()

        if raw_data:
            encoded_data = json.loads(raw_data)
            data = cbor.loads(base64.b64decode(encoded_data['data']))
            symmetric_key = self._decrypt_symmetric_key(data['permissions'])

            batch_list = self._generate_batch_list(signer_public_key, symmetric_key)

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
        else:
            print('error: could not find certificate')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--certificate', help="identifier of certificate", required=True)
    parser.add_argument('--subject', help='subject identifier', required=True)
    parser.add_argument('--secret', help='subject that is performing management', required=True)
    parser.add_argument('-r', '--remove', help='remove existing permissions', action='store_true')
    args = parser.parse_args()

    manager = PermissionsManager(args.certificate, args.subject, args.secret, args.remove)
    manager.main()
