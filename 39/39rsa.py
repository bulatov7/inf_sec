import math
from Cryptodome.Util.number import getStrongPrime


def enc(f, n, e):

    if n==1:
        return 0
    c=1
    for i in range(e):
        c=(c*f)%n
    return c


def dec(f, n, d):
    if n==1:
        return 0
    c=1
    for i in range(d):
        c=(c*f)%n
    return c


def egcd(e, t):
    f=False
    i=1
    while not f:
        if (e*i)%t==1:
            f=True
        else:
            i+=1
    return i


def main():
    p, q, d = int(getStrongPrime(512)), int(getStrongPrime(512)), 0
    n=p*q
    t=(p-1)*(q-1)
    e=3

    print("p = ", p)
    print("q = ", q)
    print("e = ", e)
    print("t = ", t)
    print("n = ", n)
    
    enc=enc(42, n, e)
    print(enc)

    d=egcd(e, t)
    print("d = ", d)
    print(dec(enc, n, d))




if __name__ == "__main__":
    main()