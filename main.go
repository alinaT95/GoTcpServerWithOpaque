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
var p256 = opaque.GetDhGroup()
var privS opaque.ECPrivateKey
var pubS opaque.ECPoint


// Map usernames to users.
var users = map[string]*opaque.User{}

func main() {
	fmt.Println("Start server...")
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
	privS = opaque.ECPrivateKey{PrivateKeyBytes: sk}
	pubS = opaque.ECPoint{X: x, Y: y}

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
	fmt.Println("Got connection from %s", conn.RemoteAddr())
	if err := doHandleConn(conn); err != nil {
		fmt.Println("Error happened in handleConn: %s\n", err)
	}
}

func doHandleConn(conn net.Conn) error {
	r := bufio.NewReader(conn)
	fmt.Println("Start connection handling...")
	cmd, err := opaque.Read(r)
	if err != nil {
		return err
	}
	fmt.Println("Command from client = " + string(cmd))
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

type BigInt struct {
	big.Int
}

func (i *BigInt) UnmarshalJSON(b []byte) error {
	var val string
	err := json.Unmarshal(b, &val)
	if err != nil {
		return err
	}

	i.SetString(val, 10)

	return nil
}

func handleAuth(r *bufio.Reader, w *bufio.Writer) error {
	fmt.Println("Start client authentication...")
	data1, err := opaque.Read(r)
	if err != nil {
		return err
	}

	var msg1 opaque.AuthMsg1
	if err := json.Unmarshal([]byte(opaque.RemoveQuotesFromJson(string(data1))), &msg1); err != nil {
		return err
	}

	fmt.Println("Got data from client #1:")
	fmt.Println("====================================")
	fmt.Println("Username:")
	fmt.Println(msg1.Username)
	fmt.Println("Point A:")
	fmt.Println("X: " + msg1.A.X.String())
	fmt.Println("Y: "+ msg1.A.Y.String())
	fmt.Println("EphemeralPubU:")
	fmt.Println("X: " + msg1.EphemeralPubU.X.String())
	fmt.Println("Y: "+ msg1.EphemeralPubU.Y.String())
	fmt.Println("Nonce:")
	fmt.Println(msg1.NonceU)
	fmt.Println("====================================")


	user, ok := users[msg1.Username]
	if !ok {
		if err := opaque.Write(w, []byte("No such user")); err != nil {
			return err
		}
		return fmt.Errorf("No such user")
	}

	fmt.Println("User with username " + msg1.Username + " is found." )

	fmt.Println("Start calculating B for OPRF and common secret...")

	session, msg2, err := opaque.Auth1(&privS, user, msg1)
	if err != nil {
		return err
	}

	fmt.Println("Finished calculating B for OPRF and common secret...")

	data2, err := json.Marshal(msg2)
	if err != nil {
		return err
	}

	fmt.Println("====================================")
	fmt.Println("Prepared data for Client:")
	fmt.Println("====================================")
	fmt.Println("EphemeralPubS:")
	fmt.Println("X: " + msg2.EphemeralPubS.X)
	fmt.Println("Y: "+ msg2.EphemeralPubS.Y)
	fmt.Println("Point B:")
	fmt.Println("X: " + msg2.B.X)
	fmt.Println("Y: "+ msg2.B.Y)
	fmt.Println("NonceS:")
	fmt.Println(msg2.NonceS)
	fmt.Println("EnvU:")
	fmt.Println(msg2.EnvU)
	fmt.Println("Mac1:")
	fmt.Println(msg2.Mac1)
	fmt.Println("====================================")

	if err := opaque.Write(w, data2); err != nil {
		return err
	}

	fmt.Println("Sent data to Client")
	fmt.Println("====================================")

	data3, err := opaque.Read(r)
	if err != nil {
		return err
	}
	var msg3 opaque.AuthMsg3
	if err := json.Unmarshal(data3, &msg3); err != nil {
		return err
	}

	fmt.Println("====================================")
	fmt.Println("Got data from client #2:")
	fmt.Println("====================================")
	fmt.Println("Mac2:")
	fmt.Println(msg3.Mac2)
	fmt.Println("====================================")

	sharedSecret, err := opaque.Auth3(session, msg3)
	if err != nil {
		return err
	}

	fmt.Println("Verified Mac2 from Client succesfully!")

	if err := opaque.Write(w, []byte("ok")); err != nil {
		return err
	}

	fmt.Println("Authentication finished!")

	fmt.Println("Session key:")
	fmt.Println(string(sharedSecret))
	return nil
}

func handlePwReg(r *bufio.Reader, w *bufio.Writer) error {
	fmt.Println("Start client registration...")
	data1, err := opaque.Read(r)
	if err != nil {
		return err
	}
	var msg1 opaque.PwRegMsg1

	if err := json.Unmarshal([]byte(opaque.RemoveQuotesFromJson(string(data1))), &msg1); err != nil {
		return err
	}

	fmt.Println("Got data from client #1:")
	fmt.Println("====================================")
	fmt.Println("Username:")
	fmt.Println(msg1.Username)
	fmt.Println("Point A:")
	fmt.Println("X: " + msg1.A.X.String())
	fmt.Println("Y: "+ msg1.A.Y.String())
	fmt.Println("====================================")

	fmt.Println("Start calculating B for OPRF...")

	session, msg2, err := opaque.PwReg(&pubS, msg1)

	fmt.Println("Finished calculating B for OPRF...")

	fmt.Println("Prepared data for Client:")
	fmt.Println("====================================")
	fmt.Println("PubS:")
	fmt.Println("X: " + msg2.PubS.X)
	fmt.Println("Y: "+ msg2.PubS.Y)
	fmt.Println("Point B:")
	fmt.Println("X: " + msg2.B.X)
	fmt.Println("Y: "+ msg2.B.Y)
	fmt.Println("====================================")

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

	fmt.Println("Sent data to Client")

	data3, err := opaque.Read(r)
	if err != nil {
		return err
	}

	fmt.Println(string(data3))
	var msg3 opaque.PwRegMsg3
	if err := json.Unmarshal([]byte(opaque.RemoveQuotesFromJson(string(data3))), &msg3); err != nil {
		return err
	}

	fmt.Println("Got data from client #2:")
	fmt.Println("====================================")
	fmt.Println("PubU:")
	fmt.Println("X: " + msg3.PubU.X.String())
	fmt.Println("Y: "+ msg3.PubU.Y.String())
	fmt.Println("Envelope:")
	fmt.Println("X: " + msg3.EnvU)
	fmt.Println("====================================")

	user := opaque.PwReg3(session, msg3)
	if err := opaque.Write(w, []byte("Msg from Server: Registration finished!")); err != nil {
		return err
	}
	fmt.Println("Added user: " + user.Username)
	users[user.Username] = user

	fmt.Println("Number of users = " + string(len(users)))

	fmt.Println("Registration finished!")
	fmt.Println("======================================= \n")

	return nil
}
