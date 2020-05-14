import sys
from hashlib import sha1
from decimal import Decimal, getcontext
from Crypto.Util import number
from random import randint


def random_byte(size):
    i = randint(0, 2 ** (8 * size))
    return i.to_bytes(size, sys.byteorder)

def invmod(a, n):
    t, r = 0, n
    t2, r2 = 1, a

    while r2!=0:
        priv=r//r2
        t, t2 = t2, t-priv*t2
        r, r2 = r2, r-priv*r2
    if t<0:
        t=t+n
    if r>1:
        raise Exception("a is irreversible")
    return t

def int_byte_size(i):
    return (i.bit_length() + 7) // 8


def int2byte(n):
    return n.to_bytes((n.bit_length() + 7) // 8, 'big')




class rsa:
    def generate_pair(self, key_size=1024, e=3):
        self.e = e  
        p = number.getStrongPrime(N=key_size // 2, e=e)
        q = number.getStrongPrime(N=key_size // 2, e=e)
        self.public_key = p * q

        et = (p - 1) * (q - 1)
        self._private_key = invmod(e, et)

    def import_public_key(self, n, e=3):
        self.e = e
        self.public_key = n

    def enc(self, data):
        msg = int.from_bytes(data, "big")
        t = pow(msg, self.e, self.public_key)
        return t.to_bytes(int_byte_size(self.public_key), "big")

    def dec(self, text):
        t = int.from_bytes(text, "big")
        msg = pow(t, self._private_key, self.public_key)
        return int2byte(msg)

    def generate_signature(self, data):
        hasher = sha1()
        mod_size = int_byte_size(self.public_key)
        prefix = b"\x00\x01\xff"
        middle = b"\x00"
        padding_size = mod_size - len(prefix) - len(middle) - hasher.digest_size
        if padding_size < 0:
            raise Exception("Invalid RSA key ")
        padding = b"\xff" * padding_size
        hasher.update(data)
        return b"".join([prefix, padding, middle, hasher.digest()])

    def sign(self, data):
        return self.dec(self.generate_signature(data))

    def verify(self, data, sign):
       
        dec_sign = self.enc(sign)

        prefix = b"\x00\x01\xff"
        if not dec_sign.startswith(prefix):
            return False

        end_of_padding = dec_sign.index(b"\x00", len(prefix) - 1)
        expected_padding = b"\xff" * (end_of_padding - len(prefix))
        if dec_sign[len(prefix) : end_of_padding] != expected_padding:
            return False

        middle = b"\x00"
        end_of_middle = end_of_padding + len(middle)
        if dec_sign[end_of_padding:end_of_middle] != middle:
            return False

        hash = sha1()
        raw_hash = dec_sign[end_of_middle : end_of_middle + hash.digest_size]
        hash.update(data)

        return hash.digest() == raw_hash


def forge_signature(public_key, data):
    key_size = int_byte_size(public_key)
    prefix = b"\x00\x01\xff\x00"
    hash = sha1(data).digest()
    prefix = prefix + hash

    padding_size = key_size - len(prefix)
    block = prefix + (b"\x00" * padding_size)
    block = int.from_bytes(block, "big")
    if block >= public_key:
        raise Exception("The required block must be wrapped with a public key module")

    root = int(block**(1/3))
    if not (root ** 3).to_bytes(key_size, "big").startswith(prefix):
        raise Exception("Public key size is too small")

    return int2byte(root)


def sign_test(e=3):
    for _ in range(e):
        data = random_byte(randint(32, 1024))
        private = rsa()
        private.generate_pair()
        signature = private.sign(data)

        public = rsa()
        public.import_public_key(private.public_key)

        if not public.verify(data, signature):
            return False
    return True


def forge_test():
    text = b"flamingo"  

    private = rsa()
    private.generate_pair()

    forged_signature = forge_signature(private.public_key, text)

    public = rsa()
    public.import_public_key(private.public_key)

    if not public.verify(text, forged_signature):
        return False
    return True


if sign_test():
    print("RSA Sign Test Passed!")
else:
    print("RSA Sign Test Failed!")

if forge_test():
    print("RSA Forge Test Passed!")
else:
    print("RSA Forge Test Failed!")
