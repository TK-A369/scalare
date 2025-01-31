# Scalare

A program allowing to store messages, possibly encrypted (assymetrically) and signed in a blockchain-like form. It is for a school project.

For usage, run it with `-h` option.

## Generating RSA keys

```bash
# Generate keypair - the private key is PEM by default
ssh-keygen -f alice -t rsa -m PEM
# Convert public key to PEM
ssh-keygen -f alice.pub -e -m PEM > alice.pub.pem
```
