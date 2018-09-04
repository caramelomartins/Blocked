"""
handler.py

This file contains the class for the handler logic of the transaction processor
for the blocked family in Hyperledger Sawtooth.
"""
import logging

import cbor
from sawtooth_sdk.processor.exceptions import InvalidTransaction
from sawtooth_sdk.processor.handler import TransactionHandler

import addressing

LOGGER = logging.getLogger()


class BlockedHandler(TransactionHandler):

    @property
    def family_name(self):
        return addressing.addresser.FAMILY_NAME

    @property
    def family_versions(self):
        return [addressing.addresser.FAMILY_VERSION]

    @property
    def namespaces(self):
        return [addressing.addresser.NAMESPACE]

    def apply(self, transaction, context):
        # Unpack transaction.
        header = transaction.header
        payload = self._deserialize(transaction.payload)

        # Call matching method for current operation.
        operation = payload['op']
        address = addressing.addresser.make_certificate_address(payload['data']['id'].encode())

        if operation == 'issue':
            addresses = self._issue_certificate(payload['data'], address, context)
        elif operation == 'revoke':
            addresses = self._revoke_certificate(header, payload['data'], address, context)
        elif operation == 'grant_access':
            addresses = self._grant_access(header, payload['data'], address, context)
        elif operation == 'revoke_access':
            addresses = self._revoke_access(header, payload['data'], address, context)
        else:
            raise InvalidTransaction('unrecognized operation')

        print('Addresses:')
        print(addresses)

    def _issue_certificate(self, data, address, context):
        state_entries = self._get_existing_certificates(context, address)

        if state_entries:
            raise InvalidTransaction('this certificate already exists')
        else:
            return context.set_state({address: self._serialize(data)})

    def _revoke_certificate(self, header, data, address, context):
        state_entries = self._get_existing_certificates(context, address)

        if state_entries:
            certificate = self._deserialize(state_entries[0].data)

            if header.signer_public_key not in certificate['owners'] and \
                    header.signer_public_key not in certificate['owners']:
                raise InvalidTransaction('subject is not an owner of this certificate')

            certificate['certificate'] = data['certificate']

            return context.set_state({address: self._serialize(certificate)})
        else:
            raise InvalidTransaction('certificate does not exist')

    def _grant_access(self, header, data, address, context):
        state_entries = self._get_existing_certificates(context, address)

        if state_entries:
            certificate = self._deserialize(state_entries[0].data)

            if header.signer_public_key not in certificate['owners']:
                raise InvalidTransaction('subject has no permission to execute this operation')

            certificate['permissions'].append(
                {data['permissions']['id']: data['permissions']['data']}
            )

            return context.set_state({address: self._serialize(certificate)})
        else:
            raise InvalidTransaction('certificate does not exist')

    def _revoke_access(self, header, data, address, context):
        state_entries = self._get_existing_certificates(context, address)

        if state_entries:
            certificate = self._deserialize(state_entries[0].data)

            if header.signer_public_key not in certificate['owners']:
                raise InvalidTransaction('subject has no permission to execute this operation')

            permissions = []

            for p in certificate['permissions']:
                print(data['permissions']['id'])
                print(list(p.keys())[0])
                if list(p.keys())[0] != data['permissions']['id']:
                    permissions.append(p)

            print(permissions)

            certificate['permissions'] = permissions

            return context.set_state({address: self._serialize(certificate)})
        else:
            raise InvalidTransaction('certificate does not exist')

    def _serialize(self, data):
        return cbor.dumps(data)

    def _deserialize(self, data):
        return cbor.loads(data)

    def _get_existing_certificates(self, context, address):
        return context.get_state([address])
