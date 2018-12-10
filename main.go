package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	homedir "github.com/mitchellh/go-homedir"
	"github.com/pkg/errors"
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
	case "get":
		return get(tail)
	case "set":
		return set(tail)
	default:
		return fmt.Errorf("unknown arg: %s", arg)
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
		shh.Keys[user.Username] = user.Keys.PublicKeyBlock
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
	user.Password, err = requestPassword()
	if err != nil {
		return errors.Wrap(err, "request password")
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

func initShhCreateConfigAndUser(configPath string) error {
	fmt.Println("> creating new .shh")
	user, err := createUser(configPath)
	if err != nil {
		return errors.Wrap(err, "create user")
	}

	// Create initial .shh file (600)
	shh := NewShh()
	shh.Keys[user.Username] = user.Keys.PublicKeyBlock
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

// TODO enforce 600 permissions on id_rsa file and .shh when any command is run

// get a secret value by name.
func get(args []string) error {
	if len(args) != 1 {
		return errors.New("bad args: expected `get $name`")
	}
	secretName := args[0]
	shh, err := ShhFromPath(".shh")
	if err != nil {
		return err
	}
	home, err := homedir.Dir()
	if err != nil {
		return err
	}
	configPath := filepath.Join(home, ".config", "shh")
	password, err := requestPassword()
	if err != nil {
		return errors.Wrap(err, "request password")
	}
	keys, err := getKeys(configPath, password)
	if err != nil {
		return err
	}
	secret, err := base64.StdEncoding.DecodeString(shh.Secrets[secretName])
	if err != nil {
		return err
	}
	plaintext, err := rsa.DecryptOAEP(sha256.New(), rand.Reader,
		keys.PrivateKey, secret, []byte(secretName))
	if err != nil {
		return errors.Wrap(err, "decrypt secret")
	}
	fmt.Println(string(plaintext))
	return nil
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
	keys, err := getPublicKey(filepath.Join(home, ".config", "shh"))
	if err != nil {
		return errors.Wrap(err, "get public key")
	}
	byt, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, keys.PublicKey,
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
