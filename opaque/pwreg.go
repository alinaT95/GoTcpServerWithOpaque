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
	EnvU string //hex
	PubU *ECPoint
}

// PwRegServerSession keeps track of state needed on the server-side during a
// run of the password registration protocol.
type PwRegServerSession struct {
	Username string
	K        *big.Int
}

// PwRegMsg1 is the first message during password registration. It is sent from
// the client to the server.
type PwRegMsg1 struct {
	Username string
	A        *ECPoint
}

// PwRegMsg2 is the second message in password registration. Sent from server to
// client.
type PwRegMsg2 struct {
	B     Point
	PubS  Point
}

// PwRegMsg3 is the third and final message in password registration. Sent from
// client to server.
type PwRegMsg3 struct {
	EnvU string //hex string
	PubU *ECPoint
}

// PwReg PwReg1 is the processing done by the server when it has received a PwRegMsg1 struct from a client.
func PwReg(pubS *ECPoint, msg1 PwRegMsg1) (*PwRegServerSession, PwRegMsg2, error) {
	k, err := generateSalt()
	if err != nil {
		return nil, PwRegMsg2{}, err
	}
	b, err := dhOprf2(msg1.A, k)
	if err != nil {
		return nil, PwRegMsg2{}, err
	}
	session := &PwRegServerSession{
		Username: msg1.Username,
		K:        k,
	}
	msg2 := PwRegMsg2{B: Point{X: b.X.String(), Y: b.Y.String()}, PubS: Point{X: b.X.String(), Y: b.Y.String()}}
	return session, msg2, nil
}

// PwReg3 is invoked on the server after it has received a PwRegMsg3 struct from
// the client.
// The returned User struct should be stored by the server and associated with
// the username.
func PwReg3(sess *PwRegServerSession, msg3 PwRegMsg3) *User {
	// From the I-D:
	//
	//       U sends EnvU and PubU to S and erases PwdU, RwdU and all keys.
	//       S stores (EnvU, PubKeyPoint, PrivateKeyBytes, PubU, kU, vU) in a user-specific
	//       record.  If PrivateKeyBytes and PubKeyPoint are used for different users, they can
	//       be stored separately and omitted from the record.
	return &User{
		Username: sess.Username,
		K:        sess.K,
		EnvU:     msg3.EnvU,
		PubU:     msg3.PubU,
	}
}
