package rsalib

import (
	"crypto/rand"
	"errors"
	"math/big"
)

const BITS int = 2048
const EXPONENT int = 65537

var BIG_ZERO = big.NewInt(0)
var BIG_ONE = big.NewInt(1)

type PublicKey struct {
	N *big.Int
	E int
}

func (pubKey *PublicKey) Size() int {
	return (pubKey.N.BitLen() + 7) / 8
}

type PrivateKey struct {
	PublicKey
	P *big.Int
	Q *big.Int
	D *big.Int
}

func (privKey *PrivateKey) Public() *PublicKey {
	return &privKey.PublicKey
}

type RsaKeyPair struct {
	PrivateKey *PrivateKey
	PublicKey  *PublicKey
}

type RsaKeyParams struct {
	bits int
	exp  int
}

func GenerateKeyPair(params RsaKeyParams) (keyPair *RsaKeyPair, err error) {
	var bits int = params.bits
	var e int = params.exp
	if bits == 0 {
		bits = BITS
	}
	if e == 0 {
		e = EXPONENT
	}

	keyPair = new(RsaKeyPair)
	keyPair.PrivateKey, err = generatePrivateKey(bits, e)
	if err != nil {
		return nil, err
	}
	keyPair.PublicKey = keyPair.PrivateKey.Public()
	if err := checkPublicKey(keyPair.PublicKey); err != nil {
		return nil, err
	}

	return keyPair, err
}

func generatePrivateKey(bits int, exp int) (privateKey *PrivateKey, err error) {
	if bits < 64 {
		return nil, errors.New("rsalib: too few bits to generate an RSA key")
	}

	if exp == 0 {
		exp = EXPONENT
	}
	primes := make([]*big.Int, 2)
	e := big.NewInt(int64(exp))
	privateKey = new(PrivateKey)

	for {
		gcd := new(big.Int)
		primeSub1 := new(big.Int)
		// p
		primeBits := bits / 2
		for {
			primes[0], err = rand.Prime(rand.Reader, primeBits)
			if err != nil {
				return nil, err
			}
			primeSub1.Sub(primes[0], BIG_ONE)
			gcd.GCD(nil, nil, e, primeSub1)
			if gcd.Cmp(BIG_ONE) == 0 {
				break
			}
		}
		// q
		primeBits = bits - primeBits
		for {
			primes[1], err = rand.Prime(rand.Reader, primeBits)
			if err != nil {
				return nil, err
			}
			primeSub1.Sub(primes[1], BIG_ONE)
			gcd.GCD(nil, nil, e, primeSub1)
			if gcd.Cmp(BIG_ONE) == 0 {
				break
			}
		}
		// p should not be equal q
		if primes[0].Cmp(primes[1]) == 0 {
			continue
		}
		// n, phi
		n := new(big.Int).Set(BIG_ONE)
		phi := new(big.Int).Set(BIG_ONE)
		for _, prime := range primes {
			n.Mul(n, prime)
			primeSub1.Sub(prime, BIG_ONE)
			phi.Mul(phi, primeSub1)
		}
		// len(n) should be equal bits
		if n.BitLen() != bits {
			continue
		}
		// d
		d := new(big.Int)
		d.ModInverse(e, phi)
		// finally private key
		if d != nil {
			privateKey.P = primes[0]
			privateKey.Q = primes[1]
			privateKey.N = n
			privateKey.D = d
			privateKey.E = exp
			break
		}
	}

	return privateKey, nil
}

func checkPublicKey(pubKey *PublicKey) error {
	if pubKey.N == nil {
		return errors.New("rsalib: missing public modulus")
	}
	if pubKey.E < 2 {
		return errors.New("rsalib: public exponent too small")
	}
	if pubKey.E > 1<<31-1 {
		return errors.New("rsalib: public exponent too large")
	}

	return nil
}
