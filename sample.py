#!/usr/bin/env python

try:
    from Crypto.Cipher import AES
    have_pycrypto = True
except ImportError:
    have_pycrypto = False

try:
    from M2Crypto import EVP
    have_m2crypto = True
except ImportError:
    have_m2crypto = False

import base64
import hashlib
import hmac
import json
import sys
import time


def base64_url_decode(input):
    input = input.encode(u'ascii')
    input += '=' * (4 - (len(input) % 4))
    return base64.urlsafe_b64decode(input)

def parse_signed_request(input, secret, max_age=3600):
    encoded_sig, encoded_envelope = input.split('.', 1)
    envelope = json.loads(base64_url_decode(encoded_envelope))
    algorithm = envelope['algorithm']

    if algorithm != 'AES-256-CBC HMAC-SHA256' and algorithm != 'HMAC-SHA256':
        raise Exception('Invalid request. (Unsupported algorithm.)')

    if envelope['issued_at'] < time.time() - max_age:
        raise Exception('Invalid request. (Too old.)')

    if base64_url_decode(encoded_sig) != hmac.new(
            secret, msg=encoded_envelope, digestmod=hashlib.sha256).digest():
        raise Exception('Invalid request. (Invalid signature.)')

    # for requests that are signed, but not encrypted, we're done
    if algorithm == 'HMAC-SHA256':
        return envelope

    # otherwise, decrypt the payload
    if have_pycrypto:
        cipher = AES.new(secret, AES.MODE_CBC, base64_url_decode(envelope['iv']))
        decrypted = cipher.decrypt(base64_url_decode(envelope['payload']))

        # pycrypto doesn't strip PKCS5 padding, M2Crypto will though
        pad = ord(decrypted[-1])
        decrypted = decrypted[:-pad]

    elif have_m2crypto:
        c = EVP.Cipher("aes_256_cbc", secret, base64_url_decode(envelope['iv']), 0)
        decrypted = c.update(base64_url_decode(envelope['payload']))
        try:
            decrypted += c.final()
        except:
            pass

    return json.loads(decrypted.strip('\0'))

# process from stdin
input = sys.stdin.read()
secret = '13750c9911fec5865d01f3bd00bdf4db'
print json.dumps(parse_signed_request(input, secret)),
