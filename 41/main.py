from 41rsa import invmod, int2byte, RSA
from random import randint


def text_recovery(shifr, rsa_server):
    e, n = rsa_server.get_public_key()

    while True:
        s=randint(2, n-1)
        if s%n>1:
            break

    shifr2=(pow(s, e, n)*shifr)%n

    text2=rsa_server.dec(shifr2)
    inttext = int.from_bytes(text2, byteorder='big')

    r=(inttext*invmod(s, n))%n

    return int2byte(r)


class RSAServer:

    def __init__(self, rsa):
        self._rsa= sa
        self._decrypted=set()

    def get_public_key(self):
        return self._rsa.e, self._rsa.n

    def dec(self, data):
        if data in self._decrypted:
            raise Exception("This shifrtext has already been decrypted")
        self._decrypted.add(data)
        return self._rsa.dec(data)


def main():
    text=b"flamingo"
    rsa=RSA(1024)
    shifr=rsa.enc(text)
    rsa_server=rsa_server(rsa)

    goodtext=text_recovery(shifr, rsa_server)
    assert goodtext==text


if __name__ == '__main__':
    main()