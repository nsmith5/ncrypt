# `ncrypt` |  simple file encryption CLI

[![Go Report Card](https://goreportcard.com/badge/github.com/nsmith5/ncrypt)](https://goreportcard.com/report/github.com/nsmith5/ncrypt)

> NB: You probably _shouldn't_ use this! Go find you a battle tested
> encryption CLI. I'm sure its out there somewhere.

`ncrypt` is a very simple command line tool for file encryption
and decryption.

## Usage

```
Usage of ncrypt:
  -d, --decrypt         decrypt input instead of encrypt
  -i, --input string    input filename (default "stdin")
  -o, --output string   output filename (default "stdout")
      --passwd-stdin    read password from stdin
```

```bash
# Encrypt
ncrypt -i input.txt > input.txt.ncrypt
```

```bash
# Decrypt
ncrypt -i input.txt.ncrypt
```

## Design

`ncrypt` uses [argon2id](https://github.com/p-h-c/phc-winner-argon2) for key
derivation (turning your password input into an encryption key) and
[xchacha20poly1305](https://datatracker.ietf.org/doc/html/draft-arciszewski-xchacha)
for authenticated encryption.

## Why?

In a recent conversation with some folks we were dismayed at the state of
encryption of private keys output by openssl. We were wanting for a simple CLI
that used modern authenticated encryption to encrypt files with a password.
While greate libraries exist like

- [Tink](https://github.com/google/tink)
- [NaCl / libsodium](https://nacl.cr.yp.to/)

we couldn't find a simple ubiquitous encryption CLI that exposed these
libraries for command line users.

## Whats with the name?

n -> Nathan (me)

crypt -> encrypt / decrypt
