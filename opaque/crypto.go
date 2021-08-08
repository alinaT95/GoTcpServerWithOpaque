// Copyright (c) 2018 Fredrik Kuivinen, frekui@gmail.com
//
// Use of this source code is governed by the BSD-style license that can be
// found in the LICENSE file.

package opaque

import (
	"crypto/elliptic"
	"crypto/sha256"
	"hash"
	"math/big"
)

type ECPrivateKey struct {
	PrivateKeyBytes []byte
}

type ECPoint struct {
	X *big.Int
	Y *big.Int
}

type ECPubKey struct {
	PubKeyPoint *ECPoint
}

// This hash function is used as H from the I-D.
func hasher() hash.Hash {
	return sha256.New()
}

var dhGroup = elliptic.P256()

func GetDhGroup() elliptic.Curve {
	return dhGroup
}
