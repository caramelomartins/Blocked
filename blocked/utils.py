import base64
import hashlib
import json
from urllib import error, request

import pyDes
from Crypto import Random
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import AES
from sawtooth_sdk.protobuf.batch_pb2 import Batch, BatchHeader
from sawtooth_sdk.protobuf.transaction_pb2 import (Transaction,
                                                   TransactionHeader)

from addressing import addresser


def submit_batch(data):
    print('Submitting Request...', end='', flush=True)
    try:
        req = request.Request(
            'http://localhost:8008/batches',
            data,
            method='POST',
            headers={'Content-Type': 'application/octet-stream'}
        )
        resp = request.urlopen(req)
    except error.HTTPError as e:
        print('[Error]')
        resp = e.file
        exit()

    print('[OK]')

    payload = resp.read().decode()

    return json.loads(payload)['link']


def fetch_state(certificate_address):
    print('Fetching Data...', end='', flush=True)
    try:
        req = request.Request(
            'http://localhost:8008/state/{}'.format(certificate_address),
            method='GET',
            headers={'Content-Type': 'application/octet-stream'}
        )
        resp = request.urlopen(req)
    except error.HTTPError as e:
        print('[Error]')
        resp = e.file
        exit()

    print('[OK]')

    return resp.read()


def make_transaction(payload, signer, inputs, outputs):
    print('Creating Transaction...', end='', flush=True)

    # Addressing
    name = addresser.FAMILY_NAME
    version = addresser.FAMILY_VERSION

    # Signing
    signer_public_key = signer.get_public_key().as_hex()

    # Payload
    payload_hash = hashlib.sha512(payload).hexdigest()

    header = TransactionHeader(
        family_name=name,
        family_version=version,
        inputs=inputs,
        outputs=outputs,
        signer_public_key=signer_public_key,
        batcher_public_key=signer_public_key,
        dependencies=[],
        payload_sha512=payload_hash
    ).SerializeToString()

    # Sign Header.
    signature = signer.sign(header)

    transaction = Transaction(
        header=header,
        header_signature=signature,
        payload=payload
    )
    print('[OK]')

    return transaction


def make_batch(txn, signer):
    print('Creating Batch...', end='', flush=True)
    transactions = [txn]

    batch_header = BatchHeader(
        signer_public_key=signer.get_public_key().as_hex(),
        transaction_ids=[txn.header_signature for txn in transactions],
    ).SerializeToString()

    signature = signer.sign(batch_header)

    batch = Batch(
        header=batch_header,
        header_signature=signature,
        transactions=transactions
    )
    print('[OK]')

    return batch


def des_encrypt(data, symmetric_key):
    iv = Random.new().read(AES.block_size)
    aes = AES.new(symmetric_key, AES.MODE_CFB, iv)

    encoded_data = _pad(json.dumps(data))
    encrypted_data = aes.encrypt(encoded_data)

    return base64.b64encode(iv + encrypted_data)


def des_decrypt(data, symmetric_key):
    decoded_data = base64.b64decode(data)
    iv = decoded_data[:AES.block_size]

    aes = AES.new(symmetric_key, AES.MODE_CFB, iv)
    decrypted_data = aes.decrypt(decoded_data[AES.block_size:])

    return _unpad(decrypted_data).decode()


def _pad(s):
    return s + (AES.block_size - len(s) % AES.block_size) * chr(AES.block_size - len(s) % AES.block_size)


def _unpad(s):
    return s[:-ord(s[len(s)-1:])]


def decrypt_symmetric_key(permissions, rsa):
    symmetric_key = None

    for i, p in enumerate(permissions):
        try:
            print('Attempt {}...'.format(i + 1), end='', flush=True)
            symmetric_key = PKCS1_OAEP.new(rsa).decrypt(
                base64.b64decode(p[list(p.keys())[0]].encode()))
            print('[OK]')
            break
        except ValueError:
            print('[Error]')

    if not symmetric_key:
        print('error: you do not have permission to access this certificate')
        exit()
    return base64.b64decode(symmetric_key)
