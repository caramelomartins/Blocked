"""
handler.py

This file contains the class for the handler logic of the transaction processor
for the blocked family in Hyperledger Sawtooth.
"""
import logging

import cbor
from sawtooth_sdk.processor.exceptions import InvalidTransaction
from sawtooth_sdk.processor.handler import TransactionHandler

import addresser

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
        payload = self._deserialize(transaction.payload)

        # Call matching method for current operation.
        operation = payload['op']
        address = addresser.make_certificate_address(payload['data']['id'].encode())

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

            if header.signer_public_key != certificate['issuer'] and \
                    header.signer_public_key != certificate['recipient']:
                raise InvalidTransaction('subject has no permission to execute this operation')

            certificate['active'] = False

            return context.set_state({address: self._serialize(certificate)})
        else:
            raise InvalidTransaction('certificate does not exist')

    def _grant_access(self, header, data, address, context):
        state_entries = self._get_existing_certificates(context, address)

        if state_entries:
            certificate = self._deserialize(state_entries[0].data)

            if header.signer_public_key != certificate['recipient']:
                raise InvalidTransaction('subject has no permission to execute this operation')

            certificate['permissions'].append(data['subject'])

            return context.set_state({address: self._serialize(certificate)})
        else:
            raise InvalidTransaction('certificate does not exist')

    def _revoke_access(self, header, data, address, context):
        state_entries = self._get_existing_certificates(context, address)

        if state_entries:
            certificate = self._deserialize(state_entries[0].data)

            if header.signer_public_key != certificate['recipient']:
                raise InvalidTransaction('subject has no permission to execute this operation')

            certificate['permissions'].remove(data['subject'])

            return context.set_state({address: self._serialize(certificate)})
        else:
            raise InvalidTransaction('certificate does not exist')

    def _serialize(self, data):
        return cbor.dumps(data)

    def _deserialize(self, data):
        return cbor.loads(data)

    def _get_existing_certificates(self, context, address):
        return context.get_state([address])
