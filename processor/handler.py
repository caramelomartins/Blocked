import cbor
import logging
import hashlib
from sawtooth_sdk.processor.handler import TransactionHandler

import addresser


class SawtoothHandler(TransactionHandler):

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
            self._issue_certificate(payload['data'], context)

    def _issue_certificate(self, data, context):
        """"""
        address = "{}{}{}".format(
            addresser.NAMESPACE,
            hashlib.sha256(data['issuer'].encode()).hexdigest()[:32],
            hashlib.sha256(data['recipient'].encode()).hexdigest()[:32]
        )

        logger = logging.getLogger()

        context.set_state({address: cbor.dumps(data)})
