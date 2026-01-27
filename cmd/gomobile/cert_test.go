// Copyright 2015 The Go Authors.  All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"os"
	"os/exec"
	"testing"
)

func TestSignPKCS7(t *testing.T) {
	// Setup RSA key.
	block, _ := pem.Decode([]byte(testKey))
	if block == nil {
		t.Fatal("no cert")
	}
	privKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	content := "Hello world,\nThis is signed."
	cert, err := signPKCS7(rand.Reader, privKey, []byte(content))
	if err != nil {
		t.Fatal(err)
	}
	sig, err := ioutil.TempFile("", "content.rsa")
	if err != nil {
		t.Fatal(err)
	}
	sigPath := sig.Name()
	defer os.Remove(sigPath)
	if _, err := sig.Write(cert); err != nil {
		t.Fatal(err)
	}
	if err := sig.Close(); err != nil {
		t.Fatal(err)
	}

	if openssl, err := exec.LookPath("openssl"); err != nil {
		t.Log("command openssl not found, skipping")
	} else {
		cmd := exec.Command(
			openssl, "asn1parse",
			"-inform", "DER",
			"-i",
			"-in", sigPath,
		)
		if err := cmd.Run(); err != nil {
			t.Errorf("bad asn.1: %v", err)
		}
	}

	if keytool, err := exec.LookPath("keytool"); err != nil {
		t.Log("command keytool not found, skipping")
	} else if err := exec.Command(keytool, "-v").Run(); err != nil {
		t.Logf("command keytool not functioning: %s, skipping", err)
	} else {
		cmd := exec.Command(keytool, "-v", "-printcert", "-file", sigPath)
		out, err := cmd.CombinedOutput()
		t.Logf("%v:\n%s", cmd.Args, out)
		if err != nil {
			t.Errorf("keytool cannot parse signature: %v", err)
		}
	}
}

