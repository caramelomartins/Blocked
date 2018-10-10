# blocked

Python implementation of an Access Control application, for Educational Certificates, based on a blockchain.

# Usage

## Environment

```
$ docker-compose up
```

## Processor

To start the execution of the Transaction Processor:

```
$ python processor/main.py
```

To finish it, just use `Ctrl+C`.

## Scripts

### Issuer

```
$ ./cert-issuer --help
usage: cert-issuer [-h] --recipient RECIPIENT --secret SECRET --recipient-rsa
                   RECIPIENT_RSA --issuer-rsa ISSUER_RSA

optional arguments:
  -h, --help            show this help message and exit
  --recipient RECIPIENT
                        Recipient's DSA Public Key'
  --secret SECRET       Issuer's DSA Private Key
  --recipient-rsa RECIPIENT_RSA
                        Path to Recipient's RSA Public Key
  --issuer-rsa ISSUER_RSA
                        Path to Issuer's RSA Public Key
```

### Revoker

```
$ ./cert-revoker --help
usage: cert-revoker [-h] -c CERTIFICATE --secret-dsa SECRET_DSA --secret-rsa
                    SECRET_RSA

optional arguments:
  -h, --help            show this help message and exit
  -c CERTIFICATE, --certificate CERTIFICATE
                        identifier of certificate
  --secret-dsa SECRET_DSA
                        secret DSA key to validate identity
  --secret-rsa SECRET_RSA
                        secret RSA key to decrypt the data
```

### Viewer

```
$ ./cert-viewer --help
usage: cert-viewer [-h] --certificate CERTIFICATE --secret-dsa SECRET_DSA
                   --secret-rsa SECRET_RSA

optional arguments:
  -h, --help            show this help message and exit
  --certificate CERTIFICATE
                        identifier of certificate
  --secret-dsa SECRET_DSA
                        secret DSA key to validate identity
  --secret-rsa SECRET_RSA
                        secret RSA key to decrypt the data
```

### Access Manager

```
$ ./access-manager --help
usage: access-manager [-h] -c CERTIFICATE --subject-dsa SUBJECT_DSA
                      --subject-rsa SUBJECT_RSA --secret-dsa SECRET_DSA
                      --secret-rsa SECRET_RSA [-r]

optional arguments:
  -h, --help            show this help message and exit
  -c CERTIFICATE, --certificate CERTIFICATE
                        identifier of certificate
  --subject-dsa SUBJECT_DSA
                        subject DSA identifier
  --subject-rsa SUBJECT_RSA
                        subject RSA identifier
  --secret-dsa SECRET_DSA
                        owner that is performing management
  --secret-rsa SECRET_RSA
                        secret RSA key to decrypt the data
  -r, --remove          remove existing permissions
```
