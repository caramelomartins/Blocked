# blocked

Python implementation of an Access Control application, for Educational Certificates, based on a blockchain. This implementation is based on the submission for HICSS 52, [Assessing Human Perception towards BlockChain’s Security and Complexity Applied to an Educational Certificates Case](https://www.dropbox.com/s/owlleypnx2ukfpc/201806-CP-001.pdf?dl=0). Other implementations for this project are [camunda-ac](https://gitlab.com/caramelomartins/camunda-ac) and [central](https://gitlab.com/caramelomartins/central).

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
$ ./blocked/cert-issuer.py --help
usage: cert-issuer.py [-h] --recipient RECIPIENT --secret SECRET
                      --recipient-rsa RECIPIENT_RSA --issuer-rsa ISSUER_RSA

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
$ ./blocked/cert-revoker.py --help
usage: cert-revoker.py [-h] -c CERTIFICATE --secret-dsa SECRET_DSA
                       --secret-rsa SECRET_RSA

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
$ ./blocked/cert-viewer.py --help
usage: cert-viewer.py [-h] --certificate CERTIFICATE --secret-dsa SECRET_DSA
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

### Manager

```
$ ./blocked/manager.py --help
usage: manager.py [-h] -c CERTIFICATE --subject-dsa SUBJECT_DSA --subject-rsa
                  SUBJECT_RSA --secret-dsa SECRET_DSA --secret-rsa SECRET_RSA
                  [-r]

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
