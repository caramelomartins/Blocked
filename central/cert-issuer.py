import cbor
import datetime
import json
import urllib.request
from hashlib import sha512, sha256
from urllib.error import HTTPError

from sawtooth_sdk.protobuf.batch_pb2 import Batch, BatchHeader, BatchList
from sawtooth_sdk.protobuf.transaction_pb2 import (Transaction,
                                                   TransactionHeader)
from sawtooth_signing import CryptoFactory, create_context

from processor import addresser

context = create_context('secp256k1')
private_key = context.new_random_private_key()
signer = CryptoFactory(context).new_signer(private_key)

signer_pkey = signer.get_public_key().as_hex()

payload = {
    'op': 'issue',
    'data': {
        'issuer': signer_pkey,
        'recipient': signer_pkey,
        'issuer_at': str(datetime.datetime.now()),
        'content': 'test'
    }
}

payload_bytes = cbor.dumps(payload)

address = "{}{}{}".format(
    addresser.NAMESPACE,
    sha256(signer_pkey.encode()).hexdigest()[:32],
    sha256(signer_pkey.encode()).hexdigest()[:32]
)

print(address)

txn_header_bytes = TransactionHeader(
    family_name=addresser.FAMILY_NAME,
    family_version=addresser.FAMILY_VERSION,
    inputs=[address],
    outputs=[address],
    signer_public_key=signer_pkey,
    batcher_public_key=signer_pkey,
    dependencies=[],
    payload_sha512=sha512(payload_bytes).hexdigest()
).SerializeToString()


signature = signer.sign(txn_header_bytes)

txn = Transaction(
    header=txn_header_bytes,
    header_signature=signature,
    payload=payload_bytes
)


txns = [txn]

batch_header_bytes = BatchHeader(
    signer_public_key=signer.get_public_key().as_hex(),
    transaction_ids=[txn.header_signature for txn in txns],
).SerializeToString()

signature = signer.sign(batch_header_bytes)

batch = Batch(
    header=batch_header_bytes,
    header_signature=signature,
    transactions=txns
)

batch_list_bytes = BatchList(batches=[batch]).SerializeToString()

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
