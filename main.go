package main

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/spf13/pflag"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/ssh/terminal"
)

const (
	time      = 1
	memory    = 128 * 1024
	threads   = 4
	keylength = 32
)

// Encrypt input using argon2 and xchacha20poly1305
func Encrypt(passwd, input []byte) ([]byte, error) {
	// Make salt / nonce!
	nonce := make([]byte, chacha20poly1305.NonceSizeX, chacha20poly1305.NonceSizeX+len(input)+chacha20poly1305.Overhead)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	key := argon2.IDKey(passwd, nonce, time, memory, threads, keylength)
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}

	return aead.Seal(nonce, nonce, input, nil), nil
}

// Decrypt input using argon2 and xchacha20poly1305
func Decrypt(passwd, input []byte) ([]byte, error) {
	if len(input) < chacha20poly1305.NonceSizeX {
		return nil, errors.New(`ciphertext too short`)
	}

	nonce, ciphertext := input[:chacha20poly1305.NonceSizeX], input[chacha20poly1305.NonceSizeX:]

	key := argon2.IDKey(passwd, nonce, time, memory, threads, keylength)
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}

	// Decrypt the message and check it wasn't tampered with.
	return aead.Open(nil, nonce, ciphertext, nil)
}

func getPasswd(fromStdin bool) (string, error) {
	if fromStdin {
		passwd, err := ioutil.ReadAll(os.Stdin)
		if err != nil {
			return "", err
		}
		return string(passwd), nil
	}

	fmt.Print(`Encryption password: `)
	passwd, err := terminal.ReadPassword(0)
	if err != nil {
		return "", err
	}
	return string(passwd), nil
}

func main() {
	var (
		passwd      string
		inputFile   string
		outputFile  string
		decrypt     bool
		passwdStdin bool
	)

	// Flags
	pflag.BoolVarP(&decrypt, "decrypt", "d", false, "decrypt input instead of encrypt")
	pflag.StringVarP(&inputFile, "input", "i", "stdin", "input filename")
	pflag.StringVarP(&outputFile, "output", "o", "stdout", "output filename")
	pflag.BoolVar(&passwdStdin, "passwd-stdin", false, "read password from stdin")
	pflag.Parse()

	// Freak out if input == stdin and passwd-stdin
	if passwdStdin && inputFile == "stdin" {
		panic(`Can't have passwd-stdin and input == stdin`)
	}

	// Get password
	passwd, err := getPasswd(passwdStdin)
	if err != nil {
		panic(err)
	}

	// Read input
	var input []byte
	if inputFile == "stdin" {
		input, err = ioutil.ReadAll(os.Stdin)
		if err != nil {
			panic(err)
		}
	} else {
		input, err = os.ReadFile(inputFile)
		if err != nil {
			panic(err)
		}
	}

	// encrypt / decrypt
	var output []byte
	if decrypt {
		output, err = Decrypt([]byte(passwd), input)
		if err != nil {
			panic(err)
		}
	} else {
		output, err = Encrypt([]byte(passwd), input)
		if err != nil {
			panic(err)
		}
	}

	// Dump output
	if outputFile == "stdout" {
		fmt.Print(string(output))
	} else {
		f, err := os.Create(outputFile)
		if err != nil {
			panic(err)
		}
		defer f.Close()

		fmt.Fprint(f, string(output))
	}
}
