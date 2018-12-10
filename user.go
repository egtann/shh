package main

import "encoding/pem"

type User struct {
	Username       string
	Password       []byte
	PublicKeyBlock *pem.Block
}
