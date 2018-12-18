package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"

	"github.com/pkg/errors"
	"golang.org/x/crypto/ssh/terminal"
)

type User struct {
	Username Username
	Password []byte
	Port     int
	Keys     *Keys
}

type Username string

type Keys struct {
	PublicKey       *rsa.PublicKey
	PrivateKey      *rsa.PrivateKey
	PublicKeyBlock  *pem.Block
	PrivateKeyBlock *pem.Block
}

// getUser from the ~/.config/shh/config file. If the user already exists in
// the project's shh key, this returns nil User and nil error.
func getUser(configPath string) (*User, error) {
	config, err := ConfigFromPath(configPath)
	if err != nil {
		return nil, err
	}

	keys, err := getPublicKey(configPath)
	if err != nil {
		return nil, errors.Wrap(err, "get public keys")
	}
	u := &User{
		Username: config.Username,
		Port:     config.Port,
		Keys:     keys,
	}
	return u, nil
}

func createUser(configPath string) (*User, error) {
	fmt.Print("username (usually email): ")
	var username string
	_, err := fmt.Scan(&username)
	if err != nil {
		return nil, err
	}
	if username == "" {
		return nil, errors.New("empty username")
	}

	password, err := requestPassword(-1, "", true)
	if err != nil {
		return nil, errors.Wrap(err, "request password")
	}
	user := &User{
		Username: Username(username),
		Password: password,
	}

	// Create ~/.config/shh folder
	err = os.MkdirAll(configPath, 0700)
	if err != nil {
		return nil, err
	}

	// Create public and private keys
	user.Keys, err = createKeys(configPath, user.Password)
	if err != nil {
		return nil, errors.Wrap(err, "create keys")
	}

	// Create initial config file (644) specifying username
	content := []byte(fmt.Sprintf("username=%s", user.Username))
	err = ioutil.WriteFile(filepath.Join(configPath, "config"), content, 0644)
	if err != nil {
		return nil, err
	}
	return user, nil
}

// requestPassword from user using the CLI. If prompt is empty, the default is
// used.
func requestPassword(port int, prompt string, confirmPass bool) ([]byte, error) {
	// Attempt to use the password from the server, if running. If any
	// error, just ask for the password.
	var password []byte
	if !confirmPass && port > 0 {
		resp, err := http.Get(fmt.Sprint("http://127.0.0.1:", port))
		if err == nil {
			defer resp.Body.Close()
			password, err = ioutil.ReadAll(resp.Body)
			if err != nil {
				return nil, errors.Wrap(err, "read all")
			}
		}
		if len(password) > 0 {
			return password, nil
		}
	}
	if prompt == "" {
		fmt.Print("password: ")
	} else {
		fmt.Print(prompt + ": ")
	}
	var err error
	password, err = terminal.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		return nil, err
	}
	fmt.Print("\n")
	if len(string(password)) < 24 {
		// The goal is to make manual entry so inconvenient that it's
		// never used. Use a password manager and a randomly generated
		// password instead.
		return nil, errors.New("password must be >= 24 chars")
	}
	if confirmPass {
		fmt.Print("confirm password: ")
		password2, err := terminal.ReadPassword(int(os.Stdin.Fd()))
		if err != nil {
			return nil, err
		}
		if string(password) != string(password2) {
			return nil, errors.New("passwords do not match")
		}
		fmt.Print("\n")
	}
	return password, nil
}

// createKeys at the given path, returning the keys and their pem block for use
// in the .shh file.
func createKeys(pth string, password []byte) (*Keys, error) {
	keys := &Keys{}
	keyPath := filepath.Join(pth, "id_rsa")

	// Generate id_rsa (600) and id_rsa.pub (644)
	var err error
	keys.PrivateKey, err = rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, err
	}
	flags := os.O_CREATE | os.O_WRONLY | os.O_EXCL
	privKeyFile, err := os.OpenFile(keyPath, flags, 0600)
	if err != nil {
		return nil, err
	}
	defer privKeyFile.Close()

	keys.PrivateKeyBlock = &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(keys.PrivateKey),
	}
	keys.PrivateKeyBlock, err = x509.EncryptPEMBlock(
		rand.Reader,
		keys.PrivateKeyBlock.Type,
		keys.PrivateKeyBlock.Bytes,
		password,
		x509.PEMCipherAES256,
	)
	if err != nil {
		return nil, err
	}
	if err = pem.Encode(privKeyFile, keys.PrivateKeyBlock); err != nil {
		return nil, err
	}

	keyPath += ".pub"
	pubKeyFile, err := os.OpenFile(keyPath, flags, 0644)
	if err != nil {
		return nil, err
	}
	defer pubKeyFile.Close()

	keys.PublicKey = keys.PrivateKey.Public().(*rsa.PublicKey)
	keys.PublicKeyBlock = &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(keys.PublicKey),
	}
	if err = pem.Encode(pubKeyFile, keys.PublicKeyBlock); err != nil {
		return nil, err
	}
	return keys, nil
}

func getPublicKey(pth string) (*Keys, error) {
	keyPath := filepath.Join(pth, "id_rsa.pub")
	byt, err := ioutil.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}
	keys := &Keys{}
	keys.PublicKeyBlock, _ = pem.Decode(byt)
	if keys.PublicKeyBlock == nil || keys.PublicKeyBlock.Type != "RSA PUBLIC KEY" {
		return nil, errors.New("failed to decode pem block for public key")
	}
	keys.PublicKey, err = x509.ParsePKCS1PublicKey(keys.PublicKeyBlock.Bytes)
	if err != nil {
		return nil, errors.Wrap(err, "parse public key")
	}

	// TODO get public key block
	return keys, nil
}

func getKeys(pth string, password []byte) (*Keys, error) {
	keyPath := filepath.Join(pth, "id_rsa")
	byt, err := ioutil.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}

	keys := &Keys{}
	keys.PrivateKeyBlock, _ = pem.Decode(byt)
	if keys.PrivateKeyBlock == nil || keys.PrivateKeyBlock.Type != "RSA PRIVATE KEY" {
		return nil, errors.New("failed to decode pem block for encrypted private key")
	}
	byt, err = x509.DecryptPEMBlock(keys.PrivateKeyBlock, password)
	if err != nil {
		return nil, errors.Wrap(err, "decrypt pem")
	}
	keys.PrivateKey, err = x509.ParsePKCS1PrivateKey(byt)
	if err != nil {
		return nil, errors.Wrap(err, "parse private key")
	}

	pubKeys, err := getPublicKey(pth)
	if err != nil {
		return nil, errors.Wrap(err, "get public keys")
	}
	keys.PublicKeyBlock = pubKeys.PublicKeyBlock
	keys.PublicKey = pubKeys.PublicKey
	return keys, nil
}
