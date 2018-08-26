import hashlib

FAMILY_NAME = 'blocked'
FAMILY_VERSION = '0.1'
NAMESPACE = hashlib.sha512(FAMILY_NAME.encode('utf-8')).hexdigest()[:6]


def _make_certificate_address(issuer, recipient):
    return "{}{}{}".format(
        NAMESPACE,
        hashlib.sha256(issuer).hexdigest()[:32],
        hashlib.sha256(recipient).hexdigest()[:32]
    )
