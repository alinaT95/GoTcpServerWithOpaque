// Copyright (c) 2018 Fredrik Kuivinen, frekui@gmail.com
//
// Use of this source code is governed by the BSD-style license that can be
// found in the LICENSE file.

package opaque

// This file contains functions to run the interactive protocol DH-OPRF
// (Diffie-Hellman Oblivious Pseudorandom Function) from the I-D
// https://tools.ietf.org/html/draft-krawczyk-cfrg-opaque-00.

import (
	"crypto/rand"
	"errors"
	"math/big"
)


func generateSalt() (k *big.Int, err error) {
	k, err = rand.Int(rand.Reader, dhGroup.Params().N)
	return
}

// dhOprf2 is the second step in computing DH-OPRF. dhOprf2 is executed on the
// server.
//
// From the I-D:
//     S: upon receiving a value a, respond with b=a^k
//
// k is used a salt when the password is hashed.
func dhOprf2(a *ECPoint, k *big.Int) (b *ECPoint, err error) {
	// From I-D: All received values (a, b, v) are checked to be non-unit
	// elements in G.
	//
	// First check that a is in Z^*_p.
	if !dhGroup.IsOnCurve(a.X, a.Y) {
		return nil,  errors.New("a is not in elliptic curve")
	}
	// Also check that a is not in a two element subgroup of dhGroup.
	/*if dhGroup.IsInSmallSubgroup(a) {
		return nil, nil, errors.New("a is in a small subgroup")
	}*/

	var xB, yB = dhGroup.ScalarMult(a.X, a.Y, k.Bytes())

	return &ECPoint{X: xB, Y: yB}, nil
}

