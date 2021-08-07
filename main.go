// Copyright (c) 2018 Fredrik Kuivinen, frekui@gmail.com
//
// Use of this source code is governed by the BSD-style license that can be
// found in the LICENSE file.

package main

import (
	"GoTcpServerWithOpaque/opaque"
	"bufio"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"flag"
	"fmt"
	"math/big"
	"net"
	"os"
)




// Server's EC key pair.
var p256 = elliptic.P256()
var privS opaque.ECPrivateKey
var pubS opaque.ECPubKey

// Map usernames to users.
var users = map[string]*opaque.User{}

func main() {
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "%s is a simple example server of the opaque package. It can be used together with cmd/client.\nUsage:\n", os.Args[0])
		flag.PrintDefaults()
	}
	addr := flag.String("l", ":9999", "Address to listen on.")
	flag.Parse()

	var err error
	var sk []byte
	var x, y *big.Int
	sk, x, y, err = elliptic.GenerateKey(p256, rand.Reader)
	privS = opaque.ECPrivateKey{PrivKeyBytes: sk}
	pubS = opaque.ECPubKey{PubKeyPoint: &opaque.ECPoint{X: x, Y: y}}

	if err != nil {
		panic(err)
	}

	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}

	for {
		conn, err := ln.Accept()
		if err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			continue
		}
		go handleConn(conn)
	}
}

func handleConn(conn net.Conn) {
	defer conn.Close()
	fmt.Printf("Got connection from %s\n", conn.RemoteAddr())
	if err := doHandleConn(conn); err != nil {
		fmt.Printf("doHandleConn: %s\n", err)
	}
}

func doHandleConn(conn net.Conn) error {
	r := bufio.NewReader(conn)
	cmd, err := opaque.Read(r)
	if err != nil {
		return err
	}
	w := bufio.NewWriter(conn)
	switch string(cmd) {
	case "pwreg":
		if err := handlePwReg(r, w); err != nil {
			return fmt.Errorf("pwreg: %s", err)
		}
	case "auth":
		if err := handleAuth(r, w); err != nil {
			return fmt.Errorf("auth: %s", err)
		}
	default:
		return fmt.Errorf("Unknown command '%s'\n", string(cmd))
	}

	return nil
}

func handleAuth(r *bufio.Reader, w *bufio.Writer) error {
	data1, err := opaque.Read(r)
	if err != nil {
		return err
	}
	var msg1 opaque.AuthMsg1
	if err := json.Unmarshal(data1, &msg1); err != nil {
		return err
	}
	user, ok := users[msg1.Username]
	if !ok {
		return fmt.Errorf("No such user")
	}
	session, msg2, err := opaque.Auth1(&privS, user, msg1)
	if err != nil {
		return err
	}

	data2, err := json.Marshal(msg2)
	if err != nil {
		return err
	}
	if err := opaque.Write(w, data2); err != nil {
		return err
	}

	data3, err := opaque.Read(r)
	if err != nil {
		return err
	}
	var msg3 opaque.AuthMsg3
	if err := json.Unmarshal(data3, &msg3); err != nil {
		return err
	}
	sharedSecret, err := opaque.Auth3(session, msg3)
	if err != nil {
		return err
	}

	if err := opaque.Write(w, []byte("ok")); err != nil {
		return err
	}

	key := sharedSecret[:16]
	toClient := "Hi client!"
	fmt.Printf("Sending '%s'\n", toClient)
	if err := opaque.EncryptAndWrite(w, key, toClient); err != nil {
		return err
	}
	plaintext, err := opaque.ReadAndDecrypt(r, key)
	if err != nil {
		return err
	}
	fmt.Printf("Received '%s'\n", plaintext)
	return nil
}

func handlePwReg(r *bufio.Reader, w *bufio.Writer) error {
	data1, err := opaque.Read(r)
	if err != nil {
		return err
	}
	var msg1 opaque.PwRegMsg1
	if err := json.Unmarshal(data1, &msg1); err != nil {
		return err
	}
	session, msg2, err := opaque.PwReg(&pubS, msg1)
	if err != nil {
		return err
	}

	data2, err := json.Marshal(msg2)
	if err != nil {
		return err
	}
	if err := opaque.Write(w, data2); err != nil {
		return err
	}

	data3, err := opaque.Read(r)
	if err != nil {
		return err
	}
	var msg3 opaque.PwRegMsg3
	if err := json.Unmarshal(data3, &msg3); err != nil {
		return err
	}
	user := opaque.PwReg3(session, msg3)
	if err := opaque.Write(w, []byte("ok")); err != nil {
		return err
	}
	fmt.Printf("Added user '%s'\n", user.Username)
	users[user.Username] = user
	return nil
}
