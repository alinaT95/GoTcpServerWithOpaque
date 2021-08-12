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
	fmt.Printf("Start server...")
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
	fmt.Printf("Got connection from %s\n", conn.RemoteAddr())
	if err := doHandleConn(conn); err != nil {
		fmt.Printf("Error happened in handleConn: %s\n", err)
	}
}

func doHandleConn(conn net.Conn) error {
	r := bufio.NewReader(conn)
	fmt.Printf("Start connection handling...")
	cmd, err := opaque.Read(r)
	if err != nil {
		return err
	}
	fmt.Printf("Start connection handling1... \n")
	fmt.Printf("command = " + string(cmd) + "\n")
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
	fmt.Println("handleAuth:")
	data1, err := opaque.Read(r)
	if err != nil {
		return err
	}
	fmt.Println(string(data1))

	var msg1 opaque.AuthMsg1
	if err := json.Unmarshal([]byte(opaque.RemoveQuotesFromJson(string(data1))), &msg1); err != nil {
		return err
	}

	fmt.Println(msg1.A.X.String())


	user, ok := users[msg1.Username]
	if !ok {
		if err := opaque.Write(w, []byte("No such user")); err != nil {
			return err
		}
		return fmt.Errorf("No such user")
	}
	fmt.Println(user)

	session, msg2, err := opaque.Auth1(&privS, user, msg1)
	if err != nil {
		return err
	}

	fmt.Println(session)

	data2, err := json.Marshal(msg2)
	if err != nil {
		return err
	}

	fmt.Println(string(data2))

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

	fmt.Printf(string(sharedSecret))

	fmt.Printf("Authentication finished!")


	return nil
}

func handlePwReg(r *bufio.Reader, w *bufio.Writer) error {
	fmt.Println("handlePwReg:")
	data1, err := opaque.Read(r)
	if err != nil {
		return err
	}
	var msg1 opaque.PwRegMsg1


	if err := json.Unmarshal([]byte(opaque.RemoveQuotesFromJson(string(data1))), &msg1); err != nil {
		return err
	}

	fmt.Println(msg1.A.X.String())

	session, msg2, err := opaque.PwReg(&pubS, msg1)


	fmt.Println(msg2.B.X)
	fmt.Println(session)

	if err != nil {
		return err
	}

	data2, err := json.Marshal(msg2)
	fmt.Println(string(data2))

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

	fmt.Println(string(data3))
	var msg3 opaque.PwRegMsg3
	if err := json.Unmarshal([]byte(opaque.RemoveQuotesFromJson(string(data3))), &msg3); err != nil {
		return err
	}

	user := opaque.PwReg3(session, msg3)
	if err := opaque.Write(w, []byte("Msg from Server: Registration finished!")); err != nil {
		return err
	}
	fmt.Printf("Added user '%s'\n", user.Username)
	users[user.Username] = user

	fmt.Println(len(users))

	fmt.Printf("Registration finished!")

	return nil
}
