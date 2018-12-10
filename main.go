package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	homedir "github.com/mitchellh/go-homedir"
	"github.com/pkg/errors"
	"golang.org/x/crypto/ssh/terminal"
)

func main() {
	if err := run(); err != nil {
		fmt.Println("error: " + err.Error())
		os.Exit(1)
	}
}

func run() error {
	flag.Parse()
	arg, tail := parseArg(flag.Args())
	if arg == "" {
		usage()
		return nil
	}
	switch arg {
	case "init":
		if tail != nil {
			return fmt.Errorf("unknown args: %v", tail)
		}
		return initShh()
	case "set":
		return set(tail)
	default:
		return fmt.Errorf("unknown arg: %s")
	}
}

// parseArg splits the arguments into a head and tail.
func parseArg(args []string) (string, []string) {
	switch len(args) {
	case 0:
		return "", nil
	case 1:
		return args[0], nil
	default:
		return args[0], args[1:]
	}
}

// initShh handling 5 possible states:
//
// 1. ~/.config/shh and .shh exist, and .shh has user (noop)
// 2. ~/.config/shh and .shh exist, but .shh is missing user (add user to shh)
// 3. ~/.config/shh exists, but .shh does not (first run in new project)
// 4. ~/.config/shh does not exist, but .shh does (first run in existing project)
// 5. ~/.config/shh and .shh are both missing (first run ever)
func initShh() error {
	home, err := homedir.Dir()
	if err != nil {
		return err
	}

	// Check for existence of config folder
	configExists := true
	configPath := filepath.Join(home, ".config", "shh")
	_, err = os.Stat(configPath)
	if os.IsNotExist(err) {
		configExists = false
	} else if err != nil {
		return err
	}

	// Check for existence of .shh secrets file
	secretExists := true
	_, err = os.Stat(".shh")
	if os.IsNotExist(err) {
		secretExists = false
	} else if err != nil {
		return err
	}

	// Check if user exists in secret file if we have a config. If not, we
	// add the user to the file before continuing
	//
	// TODO: do this on every action?
	if configExists && secretExists {
		user, err := getUser(configPath)
		if err != nil {
			return errors.Wrap(err, "get user")
		}
		shh, err := ShhFromPath(".shh")
		if err != nil {
			return err
		}
		if _, exist := shh.Keys[user.Username]; exist {
			// State 1: noop
			return nil
		}

		// State 2: .shh exists but is missing user.
		// Add user to .shh
		shh.Keys[user.Username] = user.PublicKeyBlock
		return shh.EncodeToPath(".shh")
	}

	// State 3: first run in new project
	if configExists && !secretExists {
		return initShhCreateConfig(configPath)
	}

	// State 4: first run in existing project
	if !configExists && secretExists {
		return initShhCreateUser(configPath)
	}

	// State 5: first ever run
	return initShhCreateConfigAndUser(configPath)
}

// initShhCreateConfig adds an existing user to a new .shh file.
func initShhCreateConfig(configPath string) error {
	user, err := getUser(configPath)
	if err != nil {
		return errors.Wrap(err, "get user")
	}

	// Retrieve shh, append the user's pub key, rewrite file
	shh, err := ShhFromPath(".shh")
	if err != nil {
		return err
	}
	pubKeyPath := filepath.Join(configPath, "id_rsa.pub")
	pubKeyData, err := ioutil.ReadFile(pubKeyPath)
	if err != nil {
		return errors.Wrap(err, "read")
	}
	block, _ := pem.Decode(pubKeyData)
	shh.Keys[user.Username] = block
	err = shh.EncodeToPath(".shh")
	return errors.Wrap(err, "encode to path")
}

// initShhCreateUser and add to an existing .shh file.
func initShhCreateUser(configPath string) error {
	fmt.Println("> creating user for existing .shh")
	user, err := createUser(configPath)
	if err != nil {
		return errors.Wrap(err, "create user")
	}

	// Retrieve shh, append the user's pub key, rewrite file
	pubKeyPath := filepath.Join(configPath, "id_rsa.pub")
	pubKeyData, err := ioutil.ReadFile(pubKeyPath)
	if err != nil {
		return errors.Wrap(err, "read")
	}
	block, _ := pem.Decode(pubKeyData)
	shh, err := ShhFromPath(".shh")
	if err != nil {
		return err
	}
	shh.Keys[user.Username] = block
	err = shh.EncodeToPath(".shh")
	return errors.Wrap(err, "encode to path")
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

	fmt.Print("password: ")
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
	user := &User{
		Username: username,
		Password: password,
	}

	// Create ~/.config/shh folder
	err = os.MkdirAll(configPath, 0700)
	if err != nil {
		return nil, err
	}

	// Create public and private keys
	user.PublicKeyBlock, err = createKeys(configPath, user.Password)
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

// getUser from the ~/.config/shh/config file. If the user already exists in
// the project's shh key, this returns nil User and nil error.
func getUser(configPath string) (*User, error) {
	configFilePath := filepath.Join(configPath, "config")
	config, err := ConfigFromPath(configFilePath)
	if err != nil {
		return nil, errors.Wrapf(err, "read %s", configFilePath)
	}

	block, err := getPublicKeyBlock(configPath)
	if err != nil {
		return nil, errors.Wrap(err, "get pub key block")
	}
	u := &User{
		Username:       config.Username,
		PublicKeyBlock: block,
	}

	// Check if the user already exists in the shh before continuing
	shh, err := ShhFromPath(".shh")
	if err != nil {
		return nil, err
	}
	if _, exist := shh.Keys[config.Username]; exist {
		return u, nil
	}

	fmt.Printf("> adding user %s to project\n", config.Username)
	fmt.Print("password: ")
	u.Password, err = terminal.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		return nil, err
	}
	fmt.Print("\n")
	if len(string(u.Password)) < 24 {
		// The goal is to make manual entry so inconvenient that it's
		// never used. Use a password manager and a randomly generated
		// password instead.
		return nil, errors.New("password must be >= 24 chars")
	}

	// TODO(egtann) validate password on private key and error out if bad
	return u, nil
}

func initShhCreateConfigAndUser(configPath string) error {
	fmt.Println("> creating new .shh")
	user, err := createUser(configPath)
	if err != nil {
		return errors.Wrap(err, "create user")
	}

	// Create initial .shh file (600)
	shh := NewShh()
	shh.Keys[user.Username] = user.PublicKeyBlock
	if err = shh.EncodeToPath(".shh"); err != nil {
		return err
	}
	return nil
}

func getPublicKeyBlock(pth string) (*pem.Block, error) {
	keyPath := filepath.Join(pth, "id_rsa.pub")
	byt, err := ioutil.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(byt)
	return block, nil
}

// createKeys at the given path, returning the public key pem block for use in
// the .shh file.
func createKeys(pth string, password []byte) (*pem.Block, error) {
	keyPath := filepath.Join(pth, "id_rsa")

	// Generate id_rsa (600) and id_rsa.pub (644)
	privKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, err
	}
	flags := os.O_CREATE | os.O_WRONLY | os.O_EXCL
	privKeyFile, err := os.OpenFile(keyPath, flags, 0600)
	if err != nil {
		return nil, err
	}
	defer privKeyFile.Close()

	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privKey),
	}
	block, err = x509.EncryptPEMBlock(
		rand.Reader,
		block.Type,
		block.Bytes,
		password,
		x509.PEMCipherAES256,
	)
	if err != nil {
		return nil, err
	}
	if err = pem.Encode(privKeyFile, block); err != nil {
		return nil, err
	}

	keyPath += ".pub"
	pubKeyFile, err := os.OpenFile(keyPath, flags, 0644)
	if err != nil {
		return nil, err
	}
	defer pubKeyFile.Close()

	pubKey := privKey.Public().(*rsa.PublicKey)
	block = &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(pubKey),
	}
	if err = pem.Encode(pubKeyFile, block); err != nil {
		return nil, err
	}
	return block, nil
}

// TODO enforce 600 permissions on id_rsa file and .shh when any command is run

// get a secret value by name.
func get(args []string) error {
	if len(args) != 1 {
		return errors.New("bad args: expected `get $name`")
	}
	shh, err := ShhFromPath(".shh")
	if err != nil {
		return err
	}
	// TODO finish
}

// set a secret value.
func set(args []string) error {
	if len(args) != 2 {
		return errors.New("bad args: expected `set $name $val`")
	}
	shh, err := ShhFromPath(".shh")
	if err != nil {
		return err
	}
	home, err := homedir.Dir()
	if err != nil {
		return err
	}
	configPath := filepath.Join(home, ".config", "shh")
	block, err := getPublicKeyBlock(configPath)
	if err != nil {
		return err
	}
	pubKey, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		return err
	}
	byt, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pubKey,
		[]byte(args[1]), []byte(args[0]))
	if err != nil {
		return err
	}
	shh.Secrets[args[0]] = base64.StdEncoding.EncodeToString(byt)
	err = shh.EncodeToPath(".shh")
	return errors.Wrap(err, "encode to path")
}

// del

// allow

// deny

// rotate

func usage() {
	fmt.Println(`usage:

	shh [command]

global commands:

	init			initialize store or add self to existing store
	get $name		get secret
	set $name $val		set secret
	allow $user $secret	allow user access to a secret
	deny $user $secret	deny user access to a secret
	show $user		show user's allowed and denied keys
	rotate			rotate key
`)
}
