// Copyright (c) 2018 Fredrik Kuivinen, frekui@gmail.com
//
// Use of this source code is governed by the BSD-style license that can be
// found in the LICENSE file.

package opaque

import (
	"crypto"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"hash"
	"math/big"
)

type ECPrivateKey struct {
	PrivKeyBytes []byte
}

type ECPoint struct {
	X *big.Int
	Y *big.Int
}


type ECPubKey struct {
	PubKeyPoint *ECPoint
}


var randr = rand.Reader

// This hash function is used as H from the I-D.
func hasher() hash.Hash {
	return sha256.New()
}

var hasherId = crypto.SHA256

var dhGroup = elliptic.P256()
