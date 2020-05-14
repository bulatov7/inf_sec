from base64 import b64decode
from math import ceil, log
from decimal import *


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


def gcd(a, b):
    while b!=0:
        a, b = b, a%b
    return a


def nok(a, b):
    return a//gcd(a, b)*b


class rsa46:
    def int2byte(n):
        return n.to_bytes((n.bit_length()+7)//8, 'big')

    def __init__(self, key_length):
        self.e=3
        o=0

        while gcd(self.e, o)!=1:
            p, q = getPrime(key_length//2), getPrime(key_length//2)
            o = nok(p-1, q-1)
            self.n=p*q

        self._d=invmod(self.e, o)

    def enc(self, binary_data):
        int_data = int.from_bytes(binary_data, byteorder='big')
        return pow(int_data, self.e, self.n)

    def dec(self, enc_int_data):
        int_data = pow(enc_int_data, self._d, self.n)
        return int_to_bytes(int_data)

    def is_parity_odd(self, enc_int_data):
        return pow(enc_int_data, self._d, self.n) & 1



def oracle_attack(shifr, rsa46, q=False):
   
    pr = pow(2, rsa46.e, rsa46.n)

    bot = Decimal(0)
    up = Decimal(rsa46.n)

    k = int(ceil(log(rsa46.n, 2)))

    getcontext().prec = k

    for _ in range(k):
        shifr = (shifr * pr) % rsa46.n

        if rsa46.is_parity_odd(shifr):
            bot = (bot + up) / 2
        else:
            up = (bot + up) / 2

        if q is True:
            print(int_to_bytes(int(up)))

    return int_to_bytes(int(up))


def main():
    input_bytes = b64decode("VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ==")

    rsa46 = rsa46(1024)

    shifr = rsa46.enc(input_bytes)
    rsa46.dec(shifr)

    text = oracle_attack(shifr, rsa46)
    assert text == input_bytes


if __name__ == '__main__':
    main()
