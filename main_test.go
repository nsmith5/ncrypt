package main

import (
	"testing"
)

func TestEncryptDecrypt(t *testing.T) {
	const (
		passwd = `password123`
		input  = `derpderpderp`
	)

	output, err := Encrypt([]byte(passwd), []byte(input))
	if err != nil {
		t.Fatal(err)
	}

	decrypted, err := Decrypt([]byte(passwd), output)
	if err != nil {
		t.Fatal(err)
	}

	if string(decrypted) != input {
		t.Error(`Decrypted input should match input`)
	}
}
