package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh/terminal"
)

const defaultPasswordPrompt = "password"

type user struct {
	Username username
	Password []byte
	Port     int
	Keys     *keys
}

type username string

type keys struct {
	PublicKey       *rsa.PublicKey
	PrivateKey      *rsa.PrivateKey
	PublicKeyBlock  *pem.Block
	PrivateKeyBlock *pem.Block
}

// getUser from the ~/.config/shh/config file. If the user already exists in
// the project's shh key, this returns nil User and nil error.
func getUser(configPath string) (*user, error) {
	config, err := configFromPath(configPath)
	if err != nil {
		return nil, err
	}

	keys, err := getPublicKey(configPath)
	if err != nil {
		return nil, fmt.Errorf("get public keys: %w", err)
	}
	u := &user{
		Username: config.Username,
		Port:     config.Port,
		Keys:     keys,
	}
	return u, nil
}

func createUser(configPath string) (*user, error) {
	fmt.Print("username (usually email): ")
	var uname string
	_, err := fmt.Scan(&uname)
	if err != nil {
		return nil, err
	}
	if uname == "" {
		return nil, errors.New("empty username")
	}

	password, err := requestPasswordAndConfirm(defaultPasswordPrompt)
	if err != nil {
		return nil, fmt.Errorf("request password: %w", err)
	}
	user := &user{
		Username: username(uname),
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
		return nil, fmt.Errorf("create keys: %w", err)
	}

	// Create initial config file (644) specifying username
	content := []byte(fmt.Sprintf("username=%s", user.Username))
	err = ioutil.WriteFile(filepath.Join(configPath, "config"), content, 0644)
	if err != nil {
		return nil, err
	}
	return user, nil
}

// requestPasswordFromServer and report an error if no password can be
// retrieved.
func requestPasswordFromServer(port int, resetTimer bool) ([]byte, error) {
	url := fmt.Sprint("http://127.0.0.1:", port)
	if err := pingServer(url); err != nil {
		return nil, err
	}
	if resetTimer {
		url += "/reset-timer"
	}
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	password, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read all: %w", err)
	}
	if len(password) == 0 {
		return nil, errors.New("cached password not available. run `shh login`")
	}
	return password, nil
}

// requestPassword from user using the CLI. If prompt is empty, the default is
// used. This attempts to retrieve the password from the server if configured.
func requestPassword(port int, prompt string) ([]byte, error) {
	// Attempt to use the password from the server, if running. If any
	// error, just ask for the password.
	if port > 0 {
		password, err := requestPasswordFromServer(port, false)
		if err == nil {
			return password, nil
		}
	}
	fmt.Print(prompt + ": ")
	password, err := terminal.ReadPassword(int(os.Stdin.Fd()))
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
	return password, nil
}

func requestPasswordAndConfirm(prompt string) ([]byte, error) {
	fmt.Print(prompt + ": ")
	password, err := terminal.ReadPassword(int(os.Stdin.Fd()))
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
	fmt.Print("confirm password: ")
	password2, err := terminal.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		return nil, err
	}
	if string(password) != string(password2) {
		return nil, errors.New("passwords do not match")
	}
	fmt.Print("\n")
	return password, nil
}

// createKeys at the given path, returning the keys and their pem block for use
// in the .shh file.
func createKeys(pth string, password []byte) (*keys, error) {
	keys := &keys{}
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

func getPublicKey(pth string) (*keys, error) {
	keyPath := filepath.Join(pth, "id_rsa.pub")
	byt, err := ioutil.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}
	keys := &keys{}
	keys.PublicKeyBlock, _ = pem.Decode(byt)
	if keys.PublicKeyBlock == nil || keys.PublicKeyBlock.Type != "RSA PUBLIC KEY" {
		return nil, errors.New("failed to decode pem block for public key")
	}
	keys.PublicKey, err = x509.ParsePKCS1PublicKey(keys.PublicKeyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}
	return keys, nil
}

func getKeys(pth string, password []byte) (*keys, error) {
	keyPath := filepath.Join(pth, "id_rsa")

	// Require 600 permission on private key
	fileInfo, err := os.Stat(keyPath)
	if err != nil {
		return nil, err
	}
	if fileInfo.Mode() != 0600 {
		return nil, errors.New("bad private key permission level. id_rsa mode must be set to 0600")
	}

	byt, err := ioutil.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}

	keys := &keys{}
	keys.PrivateKeyBlock, _ = pem.Decode(byt)
	if keys.PrivateKeyBlock == nil || keys.PrivateKeyBlock.Type != "RSA PRIVATE KEY" {
		return nil, errors.New("failed to decode pem block for encrypted private key")
	}
	byt, err = x509.DecryptPEMBlock(keys.PrivateKeyBlock, password)
	if err != nil {
		return nil, fmt.Errorf("decrypt pem: %w", err)
	}
	keys.PrivateKey, err = x509.ParsePKCS1PrivateKey(byt)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}

	pubkeys, err := getPublicKey(pth)
	if err != nil {
		return nil, fmt.Errorf("get public keys: %w", err)
	}
	keys.PublicKeyBlock = pubkeys.PublicKeyBlock
	keys.PublicKey = pubkeys.PublicKey
	return keys, nil
}

func pingServer(url string) error {
	resp, err := http.Get(url + "/ping")
	if err != nil {
		if strings.HasSuffix(err.Error(), "connection refused") {
			return errors.New("server not running. run `shh serve` first")
		}
		return fmt.Errorf("new request: %w", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("bad resp code: %d", resp.StatusCode)
	}
	return nil
}
