"""
handler.py

This file contains the class for the handler logic of the transaction processor
for the blocked family in Hyperledger Sawtooth.
"""
import logging

import cbor
from sawtooth_sdk.processor.exceptions import InvalidTransaction
from sawtooth_sdk.processor.handler import TransactionHandler

from addressing import addresser

LOGGER = logging.getLogger()


class BlockedHandler(TransactionHandler):

    @property
    def family_name(self):
        return addresser.FAMILY_NAME

    @property
    def family_versions(self):
        return [addresser.FAMILY_VERSION]

    @property
    def namespaces(self):
        return [addresser.NAMESPACE]

    def apply(self, transaction, context):
        # Unpack transaction.
        header = transaction.header
        payload = _deserialize(transaction.payload)

        # Call matching method for current operation.
        if not 'op' in payload:
            raise InvalidTransaction('invalid payload schema - no operation')
        operation = payload['op']

        # Get Certificate ID and Address. This will be used throughout regardless
        # of the operation.
        if not ('data' in payload and 'id' in payload['data']):
            raise InvalidTransaction('invalid payload schema - no certificate id')

        certificate_identifier = payload['data']['id']
        certificate_address = addresser.make_certificate_address(certificate_identifier.encode())

        # verify that the certificate we are dealing with exists.
        certificates = _get_existing_certificates(context, certificate_address)

        # Handle operation.
        if not certificates:
            raise InvalidTransaction('certificate does not exist')

        certificate = _deserialize(certificates[0].data)

        if operation == 'issue':
            addresses = _issue_certificate(payload['data'], certificate_address, context)
        elif operation == 'revoke':
            addresses = _revoke_certificate(
                header, payload['data'], certificate_address, certificate, context
            )
        elif operation == 'grant_access':
            addresses = _grant_access(
                header, payload['data'], certificate_address, certificate, context
            )
        elif operation == 'revoke_access':
            addresses = _revoke_access(
                header, payload['data'], certificate_address, certificate, context
            )
        else:
            raise InvalidTransaction('unrecognized operation')

        print('Addresses:')
        print(addresses)


def _issue_certificate(data, address, context):
    return context.set_state({address: _serialize(data)})


def _revoke_certificate(header, data, address, certificate, context):
    signer = header.signer_public_key
    owners = certificate['owners']

    if signer not in owners:
        raise InvalidTransaction('subject is not an owner of this certificate')

    certificate['certificate'] = data['certificate']

    return context.set_state({address: _serialize(certificate)})


def _grant_access(header, data, address, certificate, context):
    signer = header.signer_public_key
    owners = certificate['owners']

    if signer not in owners:
        raise InvalidTransaction('subject has no permission to execute this operation')

    if not 'permissions' in data:
        raise InvalidTransaction('invalid payload schema - no permissions')

    if not 'id' in data['permissions']:
        raise InvalidTransaction('invalid payload schema - no identifier')

    if not 'data' in data['permissions']:
        raise InvalidTransaction('invalid payload schema - no encrypted key')

    identifier = data['permissions']['id']
    encrypted_key = data['permissions']['data']

    data = {
        identifier: encrypted_key
    }
    certificate['permissions'].append(data)

    return context.set_state({address: _serialize(certificate)})


def _revoke_access(header, data, address, certificate, context):
    signer = header.signer_public_key
    owners = certificate['owners']

    if signer not in owners:
        raise InvalidTransaction('subject has no permission to execute this operation')

    permissions = []

    for p in certificate['permissions']:
        # Append every permissions that doesn't match the identifier that has been
        # sent in the payload, this will overwrite the current permissions and
        # remove the access.
        if list(p.keys())[0] != data['permissions']['id']:
            permissions.append(p)

    certificate['permissions'] = permissions

    return context.set_state({address: _serialize(certificate)})


def _serialize(data):
    return cbor.dumps(data)


def _deserialize(data):
    return cbor.loads(data)


def _get_existing_certificates(context, address):
    return context.get_state([address])
