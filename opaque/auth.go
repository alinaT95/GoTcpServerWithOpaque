// Copyright (c) 2018 Fredrik Kuivinen, frekui@gmail.com
//
// Use of this source code is governed by the BSD-style license that can be
// found in the LICENSE file.

package opaque

import (
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"golang.org/x/crypto/hkdf"
	"io"
	"math/big"
)

// AuthServerSession keeps track of state needed on the server-side during a
// run of the authentication protocol.
type AuthServerSession struct {
	SK []byte
	Km2 []byte
	Km3 []byte
	NonceU string
	NonceS string
	EphemeralPrivS *ECPrivateKey
	EphemeralPubS *ECPoint
	user *User
	XCrypt []byte
}

// AuthMsg1 is the first message in the authentication protocol. It is sent from
// the client to the server.
type AuthMsg1 struct {
	Username string
	A *ECPoint
	NonceU string //hex
	EphemeralPubU *ECPoint
}

// AuthMsg2 is the second message in the authentication protocol. It is sent
// from the server to the client.
type AuthMsg2 struct {
	// k below is the salt.
	// b=a^k
	B *Point

	// EnvU contains data encrypted by the client which is stored
	// server-side.
	EnvU string

	EphemeralPubS *Point

	NonceS string

	Mac1 string
}

// After receiving AuthMsg2 client can compute RwdU as H(x, v, b*v^{-r}).
//
// Client can now decrypt envU, which contains PrivU and PubKeyPoint. Using PubKeyPoint the
// client can verify the signature AuthMsg2.DhSig. With PrivU the client can
// compute AuthMsg3.DhSig.

// AuthMsg3 is the third and final message in the authentication protocol. It is sent from
// the client to the server.
//
// Users of package opaque does not need to read nor write to any fields in this
// struct except to serialize and deserialize the struct when it's sent between
// the peers in the authentication protocol.
type AuthMsg3 struct {
	Mac2 string
}


// Auth1 is the processing done by the server when it receives an AuthMsg1
// struct. On success a nil error is returned together with a AuthServerSession
// and an AuthMsg2 struct. The AuthMsg2 struct should be sent to the client.
func Auth1(privS *ECPrivateKey, user *User, msg1 AuthMsg1) (*AuthServerSession, AuthMsg2, error) {
	var err error
	var sk []byte
	var x, y *big.Int
	sk, x, y, err = elliptic.GenerateKey(dhGroup, rand.Reader)
	if err != nil {
		return nil, AuthMsg2{}, err
	}
	var EPrivateS = ECPrivateKey{PrivateKeyBytes: sk}
	var EPubS = ECPoint{X: x, Y: y}

	var msg2 AuthMsg2
	var B, err1 = dhOprf2(msg1.A, user.K)
	if err1 != nil {
		return nil, AuthMsg2{}, err
	}
	msg2.B =  &Point{X: B.X.String(), Y: B.Y.String()}
	msg2.EnvU = user.EnvU
	msg2.EphemeralPubS =  &Point{X: EPubS.X.String(), Y: EPubS.Y.String()}

	NonceS := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, NonceS); err != nil {
		panic(err.Error())
	}

	msg2.NonceS = hex.EncodeToString(NonceS[:])

	//XCrypt is a message for signing

	fmt.Println(len(msg1.A.X.Bytes()))
	fmt.Println(len(msg1.A.Y.Bytes()))

	var decodedNonceU,err2 = hex.DecodeString(msg1.NonceU)

	if err2 != nil {
		panic(err)
	}

	var decodedEnvU,err3 = hex.DecodeString(msg2.EnvU)

	if err3 != nil {
		panic(err)
	}

	var XCrypt = append(msg1.A.X.Bytes(), msg1.A.Y.Bytes()...)
	XCrypt = append(XCrypt, decodedNonceU...)
	XCrypt = append(XCrypt, []byte(msg1.Username)...)
	XCrypt = append(XCrypt, msg1.EphemeralPubU.X.Bytes()...)
	XCrypt = append(XCrypt, msg1.EphemeralPubU.Y.Bytes()...)
	XCrypt = append(XCrypt, B.X.Bytes()...)
	XCrypt = append(XCrypt, B.Y.Bytes()...)
	XCrypt = append(XCrypt, decodedEnvU...)
	XCrypt = append(XCrypt, NonceS...)
	XCrypt = append(XCrypt, EPubS.X.Bytes()...)
	XCrypt = append(XCrypt, EPubS.Y.Bytes()...)

	//Prepare common secret: session key, key for mac etc

	var info = append([]byte("HMQVKeys"), decodedNonceU...)
	//info = append(info, NonceS...)
	//info = append(info, []byte(msg1.Username)...)

	fmt.Println("msg1.NonceU = ")
	fmt.Println(msg1.NonceU)

	fmt.Println("XCrypt = ")
	fmt.Println( hex.EncodeToString(XCrypt))

	fmt.Println("info = ")
	fmt.Println( hex.EncodeToString(info))

	var Q1Input = append(msg1.EphemeralPubU.X.Bytes(), msg1.EphemeralPubU.Y.Bytes()...)
	Q1Input = append(Q1Input, []byte("user")...)
	Q1Input = append(Q1Input, info...)

	var Q2Input = append(EPubS.X.Bytes(), EPubS.Y.Bytes()...)
	Q2Input = append(Q2Input, []byte("srvr")...)
	Q2Input = append(Q2Input, info...)

	var Q1 = sha256.Sum256(Q1Input)
	var Q2 = sha256.Sum256(Q2Input)

	fmt.Println("Q1 = ")
	fmt.Println(hex.EncodeToString(Q1[:]))

	fmt.Println("Q2 = ")
	fmt.Println(hex.EncodeToString(Q2[:]))

	var Q2Num = new(big.Int).SetBytes(Q2[:])
	var EPrivSNum = new(big.Int).SetBytes(EPrivateS.PrivateKeyBytes[:])
	var PrivSNum = new(big.Int).SetBytes(privS.PrivateKeyBytes[:])

	var exp = big.NewInt(0).Add(EPrivSNum, big.NewInt(1).Mul(Q2Num, PrivSNum)).Bytes()

	var xPubUQ2, yPubUQ2 = dhGroup.ScalarMult(user.PubU.X, user.PubU.Y, Q1[:])
	var xSum, ySum = dhGroup.Add(msg1.EphemeralPubU.X, msg1.EphemeralPubU.Y, xPubUQ2, yPubUQ2)
	var xIkms, yIkms = dhGroup.ScalarMult(xSum, ySum, exp)
	var secret = append(xIkms.Bytes(), yIkms.Bytes()...)

	var kdf = hkdf.New(hasher, secret, make([]byte, 32)[:], info)

	var SK = make([]byte, 32)
	if _, err := io.ReadFull(kdf, SK); err != nil {
		panic(err)
	}

	fmt.Println("xIkms = ")
	fmt.Println(xIkms)

	fmt.Println("yIkms = ")
	fmt.Println(yIkms)

	fmt.Println("SK = ")
	fmt.Println( hex.EncodeToString(SK))

	var Km2 = make([]byte, 32)
	if _, err := io.ReadFull(kdf, Km2); err != nil {
		panic(err)
	}

	fmt.Println("Km2 = ")
	fmt.Println( hex.EncodeToString(Km2))

	var Km3 = make([]byte, 32)
	if _, err := io.ReadFull(kdf, Km3); err != nil {
		panic(err)
	}

	fmt.Println("Km3 = ")
	fmt.Println( hex.EncodeToString(Km3))

	var mac1 = computeHMac(Km3, XCrypt)
	msg2.Mac1 = hex.EncodeToString(mac1)

	fmt.Println("mac1 = ")
	fmt.Println( hex.EncodeToString(mac1))

	session := &AuthServerSession{
		SK: SK,
		Km2: Km2,
		Km3: Km3,
		NonceU: msg1.NonceU,
		NonceS: hex.EncodeToString(NonceS),
		EphemeralPrivS: &EPrivateS,
		EphemeralPubS: &EPubS,
		user: user,
		XCrypt: XCrypt,
	}
	return session, msg2, nil
}


// Auth3 is the processing done by the server when it receives an AuthMsg3
// struct. On success a nil error is returned together with a secret. On
// successful completion the secret returned by this function is equal to the
// secret returned by Auth2 invoked on the client. Auth3 is the final round in
// the authentication protocol.
//
// If Auth3 returns a nil error the server has authenticated the client (i.e.,
// the client has proved to the server that it posses information used when the
// password registration protocol ran for this user).
//
// A non-nil error is returned on failure.
//
// See also AuthInit, Auth1, and Auth2.
func Auth3(sess *AuthServerSession, msg3 AuthMsg3) (secret []byte, err error) {
	var data = append([]byte("Finish"), sess.XCrypt...)
	var mac2,err1 = hex.DecodeString(msg3.Mac2)
	if err1 != nil {
		panic(err)
	}

	if !verifyHMac(sess.Km3, data, mac2) {
		return nil, errors.New("MAC mismatch")
	}
	return sess.SK, nil
}

func computeHMac(key []byte, data []byte) []byte {
	mac := hmac.New(hasher, key)
	mac.Write(data)
	return mac.Sum(nil)
}

func verifyHMac(key []byte, data []byte, origMac []byte) bool {
	mac := computeHMac(key, data)
	return hmac.Equal(mac, origMac)
}

