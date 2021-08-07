// Copyright (c) 2018 Fredrik Kuivinen, frekui@gmail.com
//
// Use of this source code is governed by the BSD-style license that can be
// found in the LICENSE file.

package opaque

// References:
// OPAQUE: An Asymmetric PAKE Protocol Secure Against Pre-Computation Attacks, https://eprint.iacr.org/2018/163.pdf
// https://tools.ietf.org/html/draft-krawczyk-cfrg-opaque-00
// http://webee.technion.ac.il/~hugo/sigma-pdf.pdf

import (
	"math/big"
)

// The User struct is the state that the server needs to store for each
// registered used. Values of this struct are created by PwReg3.
type User struct {
	// Name of this user.
	Username string

	// OPRF key for this user. This is the salt.
	K *big.Int

	// EnvU and PubU are generated by the client during password
	// registration and stored at the server.
	EnvU []byte
	PubU *ECPubKey
}

// PwRegServerSession keeps track of state needed on the server-side during a
// run of the password registration protocol.
type PwRegServerSession struct {
	Username string
	K        *big.Int
}

// PwRegMsg1 is the first message during password registration. It is sent from
// the client to the server.
//
// Users of package opaque does not need to read nor write to any fields in this
// struct except to serialize and deserialize th
type PwRegMsg1 struct {
	Username string
	A        *ECPoint
}


// PwRegMsg2 is the second message in password registration. Sent from server to
// client.
//
// Users of package opaque does not need to read nor write to any fields in this
// struct except to serialize and deserialize the struct when it's sent between
// the peers in the authentication protocol.
type PwRegMsg2 struct {
	B     *ECPoint
	PubS *ECPubKey
}

// PwRegMsg3 is the third and final message in password registration. Sent from
// client to server.
//
// Users of package opaque does not need to read nor write to any fields in this
// struct except to serialize and deserialize the struct when it's sent between
// the peers in the authentication protocol.
type PwRegMsg3 struct {
	EnvU []byte
	PubU *ECPubKey
}

// PwReg1 is the processing done by the server when it has received a PwRegMsg1
// struct from a client.
//
// privS is the server's private EC key. It can be the same for all users.
//
// A non-nil error is returned on failure.
//
// See also PwRegInit, PwReg2, and PwReg3.
func PwReg(pubS *ECPubKey, msg1 PwRegMsg1) (*PwRegServerSession, PwRegMsg2, error) {
	// From the I-D:
	//
	//    S chooses OPRF key kU (random and independent for each user U) and sets vU
	//    = g^kU; it also chooses its own pair of private-public keys PrivKeyBytes and PubKeyPoint
	//    for use with protocol KE (the server can use the same pair of keys with
	//    multiple users), and sends PubKeyPoint to U.
	//
	//    S: upon receiving a value a, respond with v=g^k and b=a^k
	k, err := generateSalt()
	if err != nil {
		return nil, PwRegMsg2{}, err
	}
	// func dhOprf2(a, k *big.Int) (v *big.Int, b *big.Int)
	b, err := dhOprf2(msg1.A, k)
	if err != nil {
		return nil, PwRegMsg2{}, err
	}
	session := &PwRegServerSession{
		Username: msg1.Username,
		K:        k,
	}
	msg2 := PwRegMsg2{B: b, PubS: pubS}
	return session, msg2, nil
}

// PwReg3 is invoked on the server after it has received a PwRegMsg3 struct from
// the client.
//
// The returned User struct should be stored by the server and associated with
// the username.
//
// See also PwRegInit, PwReg1, and PwReg2.
func PwReg3(sess *PwRegServerSession, msg3 PwRegMsg3) *User {
	// From the I-D:
	//
	//    o  U sends EnvU and PubU to S and erases PwdU, RwdU and all keys.
	//       S stores (EnvU, PubKeyPoint, PrivKeyBytes, PubU, kU, vU) in a user-specific
	//       record.  If PrivKeyBytes and PubKeyPoint are used for different users, they can
	//       be stored separately and omitted from the record.
	return &User{
		Username: sess.Username,
		K:        sess.K,
		EnvU:     msg3.EnvU,
		PubU:     msg3.PubU,
	}
}
