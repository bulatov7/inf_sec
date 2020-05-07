from 40rsa import RSA, invmod, int2byte


def china(shifr):
    c_0, c_1, c_2 = shifr[0][0], shifr[1][0], shifr[2][0]
    n_0, n_1, n_2 = shifr[0][1], shifr[1][1], shifr[2][1]
    m_s_0, m_s_1, m_s_2 = n_1*n_2, n_0*n_2, n_0*n_1

    a0 = (c_0*m_s_0*invmod(m_s_0, n_0))
    a1 = (c_1*m_s_1*invmod(m_s_1, n_1))
    a2 = (c_2*m_s_2*invmod(m_s_2, n_2))
    c =  (a0+a1+a2) % (n_0*n_1*n_2)

    return int2byte(c**(1/3))


def main():
    text=b"flamingo"
    shifr=[]
    for z in range(3):
        rsa=RSA(1024)
        shifr.append((rsa.enc(text), rsa.n))
    assert china(shifr)==text



if __name__ == '__main__':
    main()