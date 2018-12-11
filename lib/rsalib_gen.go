package rsalib

import (
	"crypto/rand"
	"errors"
	"math/big"
)

const BITS int = 2048
const PUBLIC_EXP int = 65537

var FERMA_NUMS = [5]int{3, 5, 17, 257, 65537}
var BIG_ZERO = big.NewInt(0)
var BIG_ONE = big.NewInt(1)

type PublicKey struct {
	N *big.Int
	E int
}

func (pubKey *PublicKey) Size() int {
	return (pubKey.N.BitLen() + 7) / 8
}

type PrecomputedValues struct {
	Dp   *big.Int
	Dq   *big.Int
	Qinv *big.Int
}

type PrivateKey struct {
	PublicKey
	P           *big.Int
	Q           *big.Int
	D           *big.Int
	Precomputed PrecomputedValues
}

func (privKey *PrivateKey) Public() *PublicKey {
	return &privKey.PublicKey
}

func (privKey *PrivateKey) Precompute() {
	if privKey.Precomputed.Dp != nil {
		return
	}
	// dp = d(mod p-1)
	privKey.Precomputed.Dp = new(big.Int).Sub(privKey.P, BIG_ONE)
	privKey.Precomputed.Dp.Mod(privKey.D, privKey.Precomputed.Dp)
	// dq = d(mod q-1)
	privKey.Precomputed.Dq = new(big.Int).Sub(privKey.Q, BIG_ONE)
	privKey.Precomputed.Dq.Mod(privKey.D, privKey.Precomputed.Dq)
	// qinv = q^-1(mod p)
	privKey.Precomputed.Qinv = new(big.Int).ModInverse(privKey.Q, privKey.P)
}

type KeyPair struct {
	PrivateKey *PrivateKey
	PublicKey  *PublicKey
}

type KeyParams struct {
	Bits int // default is 2048
	Exp  int // default is 65537
}

func GenerateKeyPair(params *KeyParams) (keyPair *KeyPair, err error) {
	var bits int = BITS
	var e int = PUBLIC_EXP

	if params != nil && params.Bits > 0 {
		bits = params.Bits
	}
	if params != nil && params.Exp > 0 {
		e = params.Exp
	}

	keyPair = new(KeyPair)
	keyPair.PrivateKey, err = generatePrivateKey(bits, e)
	if err != nil {
		return nil, err
	}
	keyPair.PublicKey = keyPair.PrivateKey.Public()

	return keyPair, err
}

func generatePrivateKey(bits int, exp int) (privateKey *PrivateKey, err error) {
	if bits < 64 {
		return nil, errors.New("rsalib: too few bits to generate an RSA key")
	}
	err = checkPublicExp(exp)
	if err != nil {
		return nil, err
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
		d := new(big.Int).ModInverse(e, phi)
		// finally private key
		if d != nil {
			privateKey.P = primes[0]
			privateKey.Q = primes[1]
			privateKey.N = n
			privateKey.D = d
			privateKey.E = exp
			// precomputed values for the Chinese remainder algorithm
			privateKey.Precompute()
			break
		}
	}

	return privateKey, nil
}

func checkPublicExp(exp int) error {
	if exp < 2 {
		return errors.New("rsalib: public exponent too small")
	}
	if exp > 1<<31-1 {
		return errors.New("rsalib: public exponent too large")
	}

	ok := false
	for _, fnum := range FERMA_NUMS {
		if fnum == exp {
			ok = true
		}
	}
	if ok != true {
		return errors.New("rsalib: public exponent is not be in range of Ferma numbers 3, 5, 17, 257, 65537")
	}

	return nil
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
