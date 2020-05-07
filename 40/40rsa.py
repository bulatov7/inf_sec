from Cryptodome.Util.number import getPrime


def gcd(a, b):
    while b!=0:
        a, b = b, a%b
    return a


def nok(a, b):
    return a//gcd(a, b)*b


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


def int2byte(n):
    return n.to_bytes((n.bit_length()+7)//8, 'big')



class RSA:
    def __init__(self, key_length):
        self.e=3
        o=0

        while gcd(self.e, o)!=1:
            p, q = getPrime(key_length//2), getPrime(key_length//2)
            o = nok(p-1, q-1)
            self.n=p*q

        self._d=invmod(self.e, o)

    def enc(self, infbin):
        infint = int.from_bytes(infbin, byteorder='big')
        return pow(infint, self.e, self.n)

    def dec(self, encinfint):
        infint = pow(encinfint, self._d, self.n)
        return int2byte(infint)