import hashlib
import logging

import cbor
from sawtooth_sdk.processor.handler import TransactionHandler

import addresser


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
        header = transaction.header
        payload = cbor.loads(transaction.payload)

        logger = logging.getLogger()
        logger.debug(payload)

        if payload['op'] == 'issue':
            addresses = self._issue_certificate(payload['data'], context)

        logger.debug(addresses)

    def _issue_certificate(self, data, context):
        address = addresser._make_certificate_address(
            data['issuer'].encode(), data['recipient'].encode()
        )

        return context.set_state({address: cbor.dumps(data)})
