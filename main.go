package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"sync"
	"time"

	"github.com/awnumar/memguard"
)

func main() {
	err := run()
	if err != nil {
		switch err.(type) {
		case *emptyArgError:
			usage()
		case *badArgError:
			fmt.Println("error: " + err.Error())
			usage()
		default:
			fmt.Println("error: " + err.Error())
		}
		os.Exit(1)
	}
}

func run() error {
	nonInteractive := flag.Bool("n", false,
		"Non-interactive mode. Fail if shh would prompt for the password")
	shhFileName := flag.String("f", "", "Name of shh file (default .shh)")
	flag.Parse()

	arg, tail := parseArg(flag.Args())
	if arg == "" || arg == "help" {
		return &emptyArgError{}
	}
	if *shhFileName == "" {
		*shhFileName = ".shh"
	}

	// Enforce that a .shh file exists for anything for most commands
	switch arg {
	case "init", "gen-keys", "serve", "version": // Do nothing
	default:
		_, err := findShhRecursive(*shhFileName)
		if os.IsNotExist(err) {
			return fmt.Errorf("missing %s, run `shh init`",
				*shhFileName)
		}
		if err != nil {
			return err
		}
	}
	switch arg {
	case "init":
		if tail != nil {
			return fmt.Errorf("unknown args: %v", tail)
		}
		return initShh(*shhFileName)
	case "gen-keys":
		return genKeys(tail)
	case "get":
		return get(*nonInteractive, *shhFileName, tail)
	case "set":
		return set(*shhFileName, tail)
	case "del":
		return del(*shhFileName, tail)
	case "edit":
		return edit(*nonInteractive, *shhFileName, tail)
	case "allow":
		return allow(*nonInteractive, *shhFileName, tail)
	case "deny":
		return deny(*shhFileName, tail)
	case "add-user":
		return addUser(*shhFileName, tail)
	case "rm-user":
		return rmUser(*shhFileName, tail)
	case "rotate":
		return rotate(*shhFileName, tail)
	case "serve":
		return serve(tail)
	case "login":
		return login(tail)
	case "show":
		return show(*shhFileName, tail)
	case "search":
		return search(*shhFileName, tail)
	case "rename":
		return rename(*shhFileName, tail)
	case "copy":
		return copySecret(*shhFileName, tail)
	case "version":
		fmt.Println("1.6.0")
		return nil
	default:
		return &badArgError{Arg: arg}
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

// genKeys for self in ~/.config/shh.
func genKeys(args []string) error {
	if len(args) != 0 {
		return errors.New("bad args: expected none")
	}

	const (
		promises     = "stdio rpath wpath cpath tty"
		execPromises = ""
	)
	pledge(promises, execPromises)

	configPath, err := getConfigPath()
	if err != nil {
		return err
	}
	_, err = configFromPath(configPath)
	if err == nil {
		return errors.New("keys exist at ~/.config/shh, run `shh rotate` to change keys")
	}
	if _, err = createUser(configPath); err != nil {
		return err
	}
	backupReminder(true)
	return nil
}

// initShh creates your project file ".shh". If the project file already exists
// or if keys have not been generated, initShh reports an error.
//
// This can't easily have unveil applied to it because shh looks recursively up
// directories. Unveil only applies after the .shh file is found, however
// almost no logic exists after that point in this function.
func initShh(filename string) error {
	const (
		promises     = "stdio rpath wpath cpath"
		execPromises = ""
	)
	pledge(promises, execPromises)

	if _, err := os.Stat(filename); err == nil {
		return fmt.Errorf("%s exists", filename)
	}
	configPath, err := getConfigPath()
	if err != nil {
		return err
	}
	user, err := getUser(configPath)
	if err != nil {
		return fmt.Errorf("get user: %w", err)
	}
	shh, err := shhFromPath(filename)
	if err != nil {
		return fmt.Errorf("shh from path: %w", err)
	}
	shh.Keys[user.Username] = user.Keys.PublicKeyBlock
	return shh.EncodeToFile()
}

// get a secret value by name.
func get(nonInteractive bool, filename string, args []string) error {
	if len(args) != 1 {
		return errors.New("bad args: expected `get $name`")
	}

	const (
		promises     = "stdio rpath wpath cpath tty inet unveil"
		execPromises = ""
	)
	pledge(promises, execPromises)

	secretName := args[0]
	configPath, err := getConfigPath()
	if err != nil {
		return err
	}
	user, err := getUser(configPath)
	if err != nil {
		return fmt.Errorf("get user: %w", err)
	}
	shh, err := shhFromPath(filename)
	if err != nil {
		return err
	}

	// Now that we have our files, restrict further access
	unveil(configPath, "r")
	unveil(shh.path, "r")
	unveilBlock()

	secrets, err := shh.GetSecretsForUser(secretName, user.Username)
	if err != nil {
		return err
	}
	if nonInteractive {
		user.Password, err = requestPasswordFromServer(user.Port, false)
		if err != nil {
			return err
		}
	} else {
		user.Password, err = requestPassword(user.Port, defaultPasswordPrompt)
		if err != nil {
			return err
		}
	}
	keys, err := getKeys(configPath, user.Password)
	if err != nil {
		return err
	}
	for _, secret := range secrets {
		// Decrypt the AES key using the private key
		aesKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader,
			keys.PrivateKey, []byte(secret.AESKey), nil)
		if err != nil {
			return fmt.Errorf("decrypt secret: %w", err)
		}

		// Use the decrypted AES key to decrypt the secret
		aesBlock, err := aes.NewCipher(aesKey)
		if err != nil {
			return err
		}

		if len(secret.Encrypted) < aes.BlockSize {
			return errors.New("encrypted secret too short")
		}
		ciphertext := []byte(secret.Encrypted)
		iv := ciphertext[:aes.BlockSize]
		ciphertext = ciphertext[aes.BlockSize:]
		stream := cipher.NewCFBDecrypter(aesBlock, iv)
		plaintext := make([]byte, len(ciphertext))
		stream.XORKeyStream(plaintext, []byte(ciphertext))
		fmt.Print(string(plaintext))
	}
	return nil
}

// set a secret value.
func set(filename string, args []string) error {
	if len(args) != 2 {
		return errors.New("bad args: expected `set $name $val`")
	}

	const (
		promises     = "stdio rpath wpath cpath unix unveil"
		execPromises = ""
	)
	pledge(promises, execPromises)

	configPath, err := getConfigPath()
	if err != nil {
		return err
	}
	user, err := getUser(configPath)
	if err != nil {
		return err
	}
	shh, err := shhFromPath(filename)
	if err != nil {
		return err
	}

	// Now that we have our files, restrict further access
	unveil(shh.path, "rwc")
	unveilBlock()

	if _, exist := shh.Secrets[user.Username]; !exist {
		shh.Secrets[user.Username] = map[string]secret{}
	}
	key := args[0]
	plaintext := args[1]

	// Confirm that a secret under this name is not already in the global
	// namespace
	if _, exists := shh.namespace[key]; exists {
		return errors.New("key exists")
	}

	// Encrypt content for each user with access to the secret
	for username, secrets := range shh.Secrets {
		if username != user.Username {
			if _, ok := secrets[key]; !ok {
				continue
			}
		}

		// Generate an AES key to encrypt the data. We use AES-256
		// which requires a 32-byte key
		aesKey := make([]byte, 32)
		if _, err := rand.Read(aesKey); err != nil {
			return err
		}
		aesBlock, err := aes.NewCipher(aesKey)
		if err != nil {
			return err
		}

		// Encrypt the secret using the new AES key
		encrypted := make([]byte, aes.BlockSize+len(plaintext))
		iv := encrypted[:aes.BlockSize]
		if _, err := io.ReadFull(rand.Reader, iv); err != nil {
			return fmt.Errorf("read iv: %w", err)
		}
		stream := cipher.NewCFBEncrypter(aesBlock, iv)
		stream.XORKeyStream(encrypted[aes.BlockSize:], []byte(plaintext))

		// Encrypt the AES key using the public key
		pubKey, err := x509.ParsePKCS1PublicKey(shh.Keys[username].Bytes)
		if err != nil {
			return fmt.Errorf("parse public key: %w", err)
		}
		encryptedAES, err := rsa.EncryptOAEP(sha256.New(), rand.Reader,
			pubKey, aesKey, nil)
		if err != nil {
			return fmt.Errorf("reencrypt secret: %w", err)
		}

		// We base64 encode all encrypted data before passing it into
		// the .shh file
		sec := secret{
			AESKey:    base64.StdEncoding.EncodeToString(encryptedAES),
			Encrypted: base64.StdEncoding.EncodeToString(encrypted),
		}
		shh.Secrets[username][key] = sec
	}
	return shh.EncodeToFile()
}

// del deletes a secret for all users if the user has access to the secret. The
// user can manually delete secrets belonging to others, but this prevents
// accidentally deleting secrets belonging to others.
func del(filename string, args []string) error {
	if len(args) != 1 {
		return errors.New("bad args: expected `del $secret`")
	}

	const (
		promises     = "stdio rpath wpath cpath unveil"
		execPromises = ""
	)
	pledge(promises, execPromises)

	secret := args[0]
	configPath, err := getConfigPath()
	if err != nil {
		return err
	}
	user, err := getUser(configPath)
	if err != nil {
		return err
	}
	shh, err := shhFromPath(filename)
	if err != nil {
		return err
	}

	// Now that we have our files, restrict further access
	unveil(shh.path, "rwc")
	unveilBlock()

	// Confirm that the secret exists at all
	if _, exists := shh.namespace[secret]; !exists {
		return errors.New("secret does not exist")
	}

	// Get all secrets matching a search term. This throws an error if no
	// matching secrets are found.
	secretsToDelete, err := shh.GetSecretsForUser(secret, user.Username)
	if err != nil {
		return err
	}

	// Delete all matching secrets across every user in the project
	for username := range shh.Keys {
		userSecrets := shh.Secrets[username]
		for key := range secretsToDelete {
			delete(userSecrets, key)
		}
		if len(userSecrets) == 0 {
			delete(shh.Secrets, username)
		}
	}
	if err = shh.EncodeToFile(); err != nil {
		return fmt.Errorf("encode to file: %w", err)
	}
	return nil
}

// allow a user to access a secret. You must have access yourself.
func allow(nonInteractive bool, filename string, args []string) error {
	if len(args) != 2 {
		return errors.New("bad args: expected `allow $user $secret`")
	}

	const (
		promises     = "stdio rpath wpath cpath tty inet unveil"
		execPromises = ""
	)
	pledge(promises, execPromises)

	username := username(args[0])
	secretKey := args[1]

	configPath, err := getConfigPath()
	if err != nil {
		return fmt.Errorf("get config path: %w", err)
	}

	user, err := getUser(configPath)
	if err != nil {
		return fmt.Errorf("get user: %w", err)
	}

	shh, err := shhFromPath(filename)
	if err != nil {
		return err
	}

	// Now that we have our files, prevent further unveils
	unveil(configPath, "r")
	unveil(shh.path, "rwc")
	unveilBlock()

	block, exist := shh.Keys[username]
	if !exist {
		return fmt.Errorf("%q is not a user in the project. try `shh add-user %s $PUBKEY`", username, username)
	}
	pubKey, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("parse public key: %w", err)
	}

	// Decrypt all matching secrets
	if nonInteractive {
		user.Password, err = requestPasswordFromServer(user.Port, false)
		if err != nil {
			return err
		}
	} else {
		user.Password, err = requestPassword(user.Port, defaultPasswordPrompt)
		if err != nil {
			return err
		}
	}
	keys, err := getKeys(configPath, user.Password)
	if err != nil {
		return fmt.Errorf("get keys: %w", err)
	}
	secrets, err := shh.GetSecretsForUser(secretKey, user.Username)
	if err != nil {
		return err
	}
	if len(secrets) == 0 {
		return errors.New("no matching secrets which you can access")
	}
	if _, exist := shh.Secrets[username]; !exist {
		shh.Secrets[username] = map[string]secret{}
	}
	for key, sec := range secrets {
		// Decrypt AES key using personal RSA key
		aesKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader,
			keys.PrivateKey, []byte(sec.AESKey), nil)
		if err != nil {
			return fmt.Errorf("decrypt secret: %w", err)
		}
		aesBlock, err := aes.NewCipher(aesKey)
		if err != nil {
			return err
		}
		ciphertext := []byte(sec.Encrypted)
		iv := ciphertext[:aes.BlockSize]
		ciphertext = ciphertext[aes.BlockSize:]
		stream := cipher.NewCFBDecrypter(aesBlock, iv)
		plaintext := make([]byte, len(ciphertext))
		stream.XORKeyStream(plaintext, []byte(ciphertext))

		// Generate an AES key to encrypt the data. We use AES-256
		// which requires a 32-byte key
		aesKey = make([]byte, 32)
		if _, err := rand.Read(aesKey); err != nil {
			return err
		}
		aesBlock, err = aes.NewCipher(aesKey)
		if err != nil {
			return err
		}

		// Encrypt the secret using the new AES key
		encrypted := make([]byte, aes.BlockSize+len(plaintext))
		iv = encrypted[:aes.BlockSize]
		if _, err := io.ReadFull(rand.Reader, iv); err != nil {
			return fmt.Errorf("read iv: %w", err)
		}
		stream = cipher.NewCFBEncrypter(aesBlock, iv)
		stream.XORKeyStream(encrypted[aes.BlockSize:], []byte(plaintext))

		// Encrypt the AES key using the public key
		encryptedAES, err := rsa.EncryptOAEP(sha256.New(), rand.Reader,
			pubKey, aesKey, nil)
		if err != nil {
			return fmt.Errorf("reencrypt secret: %w", err)
		}

		// We base64 encode all encrypted data before passing it into
		// the .shh file
		sec := secret{
			AESKey:    base64.StdEncoding.EncodeToString(encryptedAES),
			Encrypted: base64.StdEncoding.EncodeToString(encrypted),
		}

		// Add encrypted data and key to .shh
		shh.Secrets[username][key] = sec
	}
	return shh.EncodeToFile()
}

// deny a user from accessing secrets.
func deny(filename string, args []string) error {
	if len(args) > 2 {
		return errors.New("bad args: expected `deny $user [$secret]`")
	}

	const (
		promises     = "stdio rpath wpath cpath inet"
		execPromises = ""
	)
	pledge(promises, execPromises)

	var secretKey string
	if len(args) == 1 {
		secretKey = "*"
	} else {
		secretKey = args[1]
	}
	username := username(args[0])
	shh, err := shhFromPath(filename)
	if err != nil {
		return err
	}
	secrets, err := shh.GetSecretsForUser(secretKey, username)
	if err != nil {
		return err
	}
	userSecrets := shh.Secrets[username]
	for key := range secrets {
		delete(userSecrets, key)
	}
	if len(userSecrets) == 0 {
		delete(shh.Secrets, username)
	}
	return shh.EncodeToFile()
}

// search owned secrets for a specific regular expression and output any
// secrets that match.
func search(filename string, args []string) error {
	if len(args) != 1 {
		return errors.New("bad args: expected `search $regex`")
	}

	const (
		promises     = "stdio rpath wpath cpath tty inet"
		execPromises = ""
	)
	pledge(promises, execPromises)

	regex, err := regexp.Compile(args[0])
	if err != nil {
		return fmt.Errorf("bad regular expression: %w", err)
	}
	shh, err := shhFromPath(filename)
	if err != nil {
		return err
	}

	// Decrypt all secrets belonging to current user
	configPath, err := getConfigPath()
	if err != nil {
		return err
	}
	user, err := getUser(configPath)
	if err != nil {
		return fmt.Errorf("get user: %w", err)
	}
	user.Password, err = requestPasswordFromServer(user.Port, true)
	if err != nil {
		return err
	}
	keys, err := getKeys(configPath, user.Password)
	if err != nil {
		return fmt.Errorf("get keys: %w", err)
	}
	secrets, err := shh.GetSecretsForUser("*", user.Username)
	if err != nil {
		return fmt.Errorf("get secrets: %w", err)
	}
	if len(secrets) == 0 {
		return errors.New("no matching secrets which you can access")
	}
	var matches []string
	for key, sec := range secrets {
		// Decrypt AES key using personal RSA key
		aesKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader,
			keys.PrivateKey, []byte(sec.AESKey), nil)
		if err != nil {
			return fmt.Errorf("decrypt secret: %w", err)
		}
		aesBlock, err := aes.NewCipher(aesKey)
		if err != nil {
			return err
		}
		ciphertext := []byte(sec.Encrypted)
		iv := ciphertext[:aes.BlockSize]
		ciphertext = ciphertext[aes.BlockSize:]
		stream := cipher.NewCFBDecrypter(aesBlock, iv)
		plaintext := make([]byte, len(ciphertext))
		stream.XORKeyStream(plaintext, []byte(ciphertext))

		// Search for the term
		if regex.Match(plaintext) {
			matches = append(matches, key)
		}
	}

	// Output secret names containing the term in separate lines (can then
	// be passed into xargs, etc.)
	for _, match := range matches {
		fmt.Println(match)
	}
	return nil
}

// rename secrets.
func rename(filename string, args []string) error {
	if len(args) != 2 {
		return errors.New("bad args: expected `rename $old $new`")
	}

	const (
		promises     = "stdio rpath wpath cpath tty unveil"
		execPromises = ""
	)
	pledge(promises, execPromises)

	oldName, newName := args[0], args[1]
	if oldName == newName {
		return errors.New("names are identical")
	}
	shh, err := shhFromPath(filename)
	if err != nil {
		return err
	}

	// Now that we have our files, restrict further access
	unveil(shh.path, "rwc")
	unveilBlock()

	if _, ok := shh.namespace[oldName]; !ok {
		return errors.New("secret does not exist")
	}
	if _, ok := shh.namespace[newName]; ok {
		return errors.New("secret already exists by that name")
	}
	for _, labelSecrets := range shh.Secrets {
		if _, ok := labelSecrets[oldName]; !ok {
			continue
		}
		labelSecrets[newName] = labelSecrets[oldName]
		delete(labelSecrets, oldName)
	}
	return shh.EncodeToFile()
}

// copySecret for each user that has access to the current secret.
func copySecret(filename string, args []string) error {
	if len(args) != 2 {
		return errors.New("bad args: expected `copy $old $new`")
	}

	const (
		promises     = "stdio rpath wpath cpath tty unveil"
		execPromises = ""
	)
	pledge(promises, execPromises)

	oldName, newName := args[0], args[1]
	if oldName == newName {
		return errors.New("names are identical")
	}
	shh, err := shhFromPath(filename)
	if err != nil {
		return err
	}

	// Now that we have our files, restrict further access
	unveil(shh.path, "rwc")
	unveilBlock()

	if _, ok := shh.namespace[oldName]; !ok {
		return errors.New("secret does not exist")
	}
	if _, ok := shh.namespace[newName]; ok {
		return errors.New("secret already exists by that name")
	}
	for _, labelSecrets := range shh.Secrets {
		if _, ok := labelSecrets[oldName]; !ok {
			continue
		}
		labelSecrets[newName] = labelSecrets[oldName]
	}
	return shh.EncodeToFile()
}

// show users and secrets which they can access.
func show(filename string, args []string) error {
	if len(args) > 1 {
		return errors.New("bad args: expected `show [$user]`")
	}
	shh, err := shhFromPath(filename)
	if err != nil {
		return err
	}
	if len(args) == 0 {
		return showAll(shh)
	}
	return showUser(shh, username(args[0]))
}

// showAll users and sorted secrets alongside a summary.
func showAll(shh *shh) error {
	secrets := shh.AllSecrets()
	fmt.Println("====== SUMMARY ======")
	fmt.Printf("%d users\n", len(shh.Keys))
	fmt.Printf("%d secrets\n", len(secrets))
	fmt.Printf("\n")
	fmt.Printf("======= USERS =======")
	usernames := []string{}
	for uname := range shh.Keys {
		usernames = append(usernames, string(uname))
	}
	sort.Strings(usernames)
	for _, uname := range usernames {
		// Sort secrets to give consistent output
		var i int
		userSecrets := shh.Secrets[username(uname)]
		secrets := make([]string, len(userSecrets))
		for secretName := range userSecrets {
			secrets[i] = secretName
			i++
		}
		sort.Strings(secrets)

		fmt.Printf("\n%s (%d secrets)\n", uname, len(userSecrets))
		for _, secret := range secrets {
			fmt.Printf("> %s\n", secret)
		}
	}
	return nil
}

// showUser secrets, sorted.
func showUser(shh *shh, username username) error {
	userSecrets, ok := shh.Secrets[username]
	if !ok {
		return fmt.Errorf("unknown user: %s", username)
	}
	var i int
	secrets := make([]string, len(userSecrets))
	for secretName := range userSecrets {
		secrets[i] = secretName
		i++
	}
	sort.Strings(secrets)
	for _, secret := range secrets {
		fmt.Printf("> %s\n", secret)
	}
	return nil
}

// edit a secret using $EDITOR.
func edit(nonInteractive bool, filename string, args []string) error {
	if len(args) != 1 {
		return errors.New("bad args: expected `edit $secret`")
	}
	if os.Getenv("EDITOR") == "" {
		return errors.New("must set $EDITOR")
	}

	const (
		promises     = "stdio rpath wpath cpath tty proc exec inet unveil"
		execPromises = "stdio rpath wpath cpath tty proc exec error"
	)
	pledge(promises, execPromises)

	configPath, err := getConfigPath()
	if err != nil {
		return err
	}
	user, err := getUser(configPath)
	if err != nil {
		return fmt.Errorf("get user: %w", err)
	}
	if nonInteractive {
		user.Password, err = requestPasswordFromServer(user.Port, false)
		if err != nil {
			return err
		}
	} else {
		user.Password, err = requestPassword(user.Port, defaultPasswordPrompt)
		if err != nil {
			return err
		}
	}
	keys, err := getKeys(configPath, user.Password)
	if err != nil {
		return err
	}

	shh, err := shhFromPath(filename)
	if err != nil {
		return err
	}
	unveil(shh.path, "rwc")

	secrets, err := shh.GetSecretsForUser(args[0], user.Username)
	if err != nil {
		return err
	}
	if len(secrets) > 1 {
		return errors.New("mulitple secrets found, cannot use *")
	}

	// Expose /tmp for creating a tmp file, a shell to run commands, our
	// configured editor, as well as necessary libraries.
	unveil("/tmp", "rwc")
	unveil("/usr", "r")
	unveil("/var/run", "r")
	unveil("/bin/sh", "x")
	unveil(os.Getenv("EDITOR"), "rx")
	unveilBlock()

	// Create tmp file
	fi, err := ioutil.TempFile("", "shh")
	if err != nil {
		return fmt.Errorf("temp file: %w", err)
	}
	defer fi.Close()

	// Copy decrypted secret into tmp file
	var plaintext, aesKey []byte
	var key string
	for k, sec := range secrets {
		key = k

		// Decrypt the AES key using the private key
		aesKey, err = rsa.DecryptOAEP(sha256.New(), rand.Reader,
			keys.PrivateKey, []byte(sec.AESKey), nil)
		if err != nil {
			return fmt.Errorf("decrypt secret: %w", err)
		}

		// Use the decrypted AES key to decrypt the secret
		aesBlock, err := aes.NewCipher(aesKey)
		if err != nil {
			return err
		}
		if len(sec.Encrypted) < aes.BlockSize {
			return errors.New("encrypted secret too short")
		}
		ciphertext := []byte(sec.Encrypted)
		iv := ciphertext[:aes.BlockSize]
		ciphertext = ciphertext[aes.BlockSize:]
		stream := cipher.NewCFBDecrypter(aesBlock, iv)
		plaintext = make([]byte, len(ciphertext))
		stream.XORKeyStream(plaintext, []byte(ciphertext))
	}
	if _, err = io.Copy(fi, bytes.NewReader(plaintext)); err != nil {
		return fmt.Errorf("copy: %w", err)
	}

	// Checksum the plaintext, so we can exit early if nothing changed
	// (i.e. don't re-encrypt on saves without changes)
	h := sha1.New()
	if _, err = h.Write(plaintext); err != nil {
		return fmt.Errorf("write hash: %w", err)
	}
	origHash := hex.EncodeToString(h.Sum(nil))

	// Open tmp file in vim
	cmd := exec.Command("/bin/sh", "-c", "$EDITOR "+fi.Name())
	cmd.Stdout = os.Stdout
	cmd.Stdin = os.Stdin
	if err = cmd.Start(); err != nil {
		return fmt.Errorf("cmd: %w", err)
	}
	if err = cmd.Wait(); err != nil {
		return fmt.Errorf("wait: %w", err)
	}

	// Check if the contents have changed. If not, we can exit early
	plaintext, err = ioutil.ReadFile(fi.Name())
	if err != nil {
		return fmt.Errorf("read all: %w", err)
	}
	h = sha1.New()
	if _, err = h.Write(plaintext); err != nil {
		return fmt.Errorf("write hash: %w", err)
	}
	newHash := hex.EncodeToString(h.Sum(nil))
	if origHash == newHash {
		return nil
	}

	// Re-encrypt content for each user with access to the secret
	for username, secrets := range shh.Secrets {
		if _, ok := secrets[key]; !ok {
			continue
		}

		// Generate an AES key to encrypt the data. We use AES-256
		// which requires a 32-byte key
		aesKey = make([]byte, 32)
		if _, err := rand.Read(aesKey); err != nil {
			return err
		}
		aesBlock, err := aes.NewCipher(aesKey)
		if err != nil {
			return err
		}

		// Encrypt the secret using the new AES key
		encrypted := make([]byte, aes.BlockSize+len(plaintext))
		iv := encrypted[:aes.BlockSize]
		if _, err := io.ReadFull(rand.Reader, iv); err != nil {
			return fmt.Errorf("read iv: %w", err)
		}
		stream := cipher.NewCFBEncrypter(aesBlock, iv)
		stream.XORKeyStream(encrypted[aes.BlockSize:], []byte(plaintext))

		// Encrypt the AES key using the public key
		pubKey, err := x509.ParsePKCS1PublicKey(shh.Keys[username].Bytes)
		if err != nil {
			return fmt.Errorf("parse public key: %w", err)
		}
		encryptedAES, err := rsa.EncryptOAEP(sha256.New(), rand.Reader,
			pubKey, aesKey, nil)
		if err != nil {
			return fmt.Errorf("reencrypt secret: %w", err)
		}

		// We base64 encode all encrypted data before passing it into
		// the .shh file
		sec := secret{
			AESKey:    base64.StdEncoding.EncodeToString(encryptedAES),
			Encrypted: base64.StdEncoding.EncodeToString(encrypted),
		}
		shh.Secrets[username][key] = sec
	}
	return shh.EncodeToFile()
}

// rotate generates new keys and re-encrypts all secrets using the new keys.
// You should also use this to change your password.
func rotate(filename string, args []string) error {
	if len(args) != 0 {
		return errors.New("bad args: expected none")
	}

	const (
		promises     = "stdio rpath wpath cpath tty"
		execPromises = ""
	)
	pledge(promises, execPromises)

	// Allow changing the password
	oldPass, err := requestPassword(-1, "old password")
	if err != nil {
		return fmt.Errorf("request old password: %w", err)
	}
	newPass, err := requestPasswordAndConfirm("new password")
	if err != nil {
		return fmt.Errorf("request new password: %w", err)
	}

	configPath, err := getConfigPath()
	if err != nil {
		return err
	}

	// Generate new keys (different names). Note we do not use os.TempDir
	// because we'll be renaming the files later, and we can't rename files
	// across partitions (common for Linux)
	tmpDir := filepath.Join(configPath, "tmp")
	if err = os.Mkdir(tmpDir, 0777); err != nil {
		return fmt.Errorf("make tmp dir: %w", err)
	}
	defer func() {
		os.RemoveAll(tmpDir)
	}()
	keys, err := createKeys(tmpDir, newPass)
	if err != nil {
		return fmt.Errorf("create keys: %w", err)
	}
	user, err := getUser(configPath)
	if err != nil {
		return fmt.Errorf("get user: %w", err)
	}

	// Decrypt all AES secrets for user, re-encrypt with new key
	oldKeys, err := getKeys(configPath, oldPass)
	if err != nil {
		return err
	}
	shh, err := shhFromPath(filename)
	if err != nil {
		return err
	}
	secrets := shh.Secrets[user.Username]
	for key, sec := range secrets {
		// Decrypt AES key using old key
		byt, err := base64.StdEncoding.DecodeString(sec.AESKey)
		if err != nil {
			return fmt.Errorf("decode base64: %w", err)
		}
		aesKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader,
			oldKeys.PrivateKey, byt, nil)
		if err != nil {
			return fmt.Errorf("decrypt secret: %w", err)
		}

		// Re-encrypt using new public key
		encryptedAES, err := rsa.EncryptOAEP(sha256.New(), rand.Reader,
			keys.PublicKey, aesKey, nil)
		if err != nil {
			return fmt.Errorf("reencrypt secret: %w", err)
		}
		shh.Secrets[user.Username][key] = secret{
			AESKey:    base64.StdEncoding.EncodeToString(encryptedAES),
			Encrypted: sec.Encrypted,
		}
	}

	// Update public key in project file
	shh.Keys[user.Username] = keys.PublicKeyBlock

	// First create backups of our existing keys
	err = copyFile(
		filepath.Join(configPath, "id_rsa.bak"),
		filepath.Join(configPath, "id_rsa"),
	)
	if err != nil {
		return fmt.Errorf("back up id_rsa: %w", err)
	}
	err = copyFile(
		filepath.Join(configPath, "id_rsa.pub.bak"),
		filepath.Join(configPath, "id_rsa.pub"),
	)
	if err != nil {
		return fmt.Errorf("back up id_rsa.pub: %w", err)
	}

	// Rewrite the project file to use the new public key
	if err = shh.EncodeToFile(); err != nil {
		return fmt.Errorf("encode %s: %w", filename, err)
	}

	// Move new keys on top of current keys in the filesystem
	err = os.Rename(
		filepath.Join(tmpDir, "id_rsa"),
		filepath.Join(configPath, "id_rsa"),
	)
	if err != nil {
		return fmt.Errorf("replace id_rsa: %w", err)
	}
	err = os.Rename(
		filepath.Join(tmpDir, "id_rsa.pub"),
		filepath.Join(configPath, "id_rsa.pub"),
	)
	if err != nil {
		return fmt.Errorf("replace id_rsa.pub: %w", err)
	}

	// Delete our backed up keys
	err = os.Remove(filepath.Join(configPath, "id_rsa.bak"))
	if err != nil {
		return fmt.Errorf("delete id_rsa.bak: %w", err)
	}
	err = os.Remove(filepath.Join(configPath, "id_rsa.pub.bak"))
	if err != nil {
		return fmt.Errorf("delete id_rsa.pub.bak: %w", err)
	}
	backupReminder(false)
	return nil
}

// addUser to project file.
func addUser(filename string, args []string) error {
	if len(args) != 0 && len(args) != 2 {
		return errors.New("bad args: expected `add-user [$user $pubkey]`")
	}

	const (
		promises     = "stdio rpath wpath cpath unveil"
		execPromises = ""
	)
	pledge(promises, execPromises)

	shh, err := shhFromPath(filename)
	if err != nil {
		return err
	}

	// Now that we have our files, restrict further access
	unveil(shh.path, "rwc")

	var u *user
	if len(args) == 0 {
		// Default to self
		configPath, err := getConfigPath()
		if err != nil {
			return err
		}
		unveil(configPath, "r")
		u, err = getUser(configPath)
		if err != nil {
			return fmt.Errorf("get user: %w", err)
		}
	} else {
		u = &user{Username: username(args[0])}
	}

	// We're done reading files
	unveilBlock()

	if _, exist := shh.Keys[u.Username]; exist {
		return nil
	}
	if len(args) == 0 {
		shh.Keys[u.Username] = u.Keys.PublicKeyBlock
	} else {
		shh.Keys[u.Username], _ = pem.Decode([]byte(args[1]))
		if shh.Keys[u.Username] == nil {
			return errors.New("bad public key")
		}
	}
	return shh.EncodeToFile()
}

// rmUser from project file.
func rmUser(filename string, args []string) error {
	if len(args) != 1 {
		return errors.New("bad args: expected `rm-user $user`")
	}

	const (
		promises     = "stdio rpath wpath cpath unveil"
		execPromises = ""
	)
	pledge(promises, execPromises)

	shh, err := shhFromPath(filename)
	if err != nil {
		return err
	}

	unveil(shh.path, "rwc")

	username := username(args[0])
	if _, exist := shh.Keys[username]; !exist {
		return errors.New("user not found")
	}
	delete(shh.Keys, username)
	delete(shh.Secrets, username)
	return shh.EncodeToFile()
}

// serve maintains the password in memory for an hour. serve cannot be pledged
// because mlock is not allowed, but we are able to unveil.
func serve(args []string) error {
	if len(args) != 0 {
		return errors.New("bad args: expected none")
	}

	configPath, err := getConfigPath()
	if err != nil {
		return err
	}
	unveil(configPath, "r")
	unveilBlock()

	user, err := getUser(configPath)
	if err != nil {
		return fmt.Errorf("get user: %w", err)
	}
	const tickTime = time.Hour
	var mu sync.Mutex

	// Clear secrets when exiting
	memguard.CatchInterrupt()
	defer memguard.Purge()

	var pwEnclave *memguard.Enclave
	resetTicker := make(chan struct{})
	ticker := time.NewTicker(tickTime)
	go func() {
		for {
			select {
			case <-resetTicker:
				ticker.Stop()
				ticker = time.NewTicker(tickTime)
			case <-ticker.C:
				mu.Lock()
				pwEnclave = nil
				mu.Unlock()
			}
		}
	}()
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/ping" {
			w.WriteHeader(http.StatusOK)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		if r.URL.Path == "/reset-timer" {
			resetTicker <- struct{}{}
		}
		if r.Method == "GET" {
			if pwEnclave == nil {
				w.WriteHeader(http.StatusOK)
				return
			}
			b, err := pwEnclave.Open()
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			defer b.Destroy()
			_, _ = w.Write(b.Bytes())
			return
		}
		byt, err := ioutil.ReadAll(r.Body)
		if len(byt) == 0 && err == nil {
			err = errors.New("empty body")
		}
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(err.Error()))
			return
		}
		pwEnclave = memguard.NewEnclave(byt)
		w.WriteHeader(http.StatusOK)
	})
	return http.ListenAndServe(fmt.Sprint(":", user.Port), mux)
}

// login to the server, caching the password in memory for 1 hour.
func login(args []string) error {
	if len(args) != 0 {
		return errors.New("bad args: expected none")
	}

	const (
		promises     = "stdio rpath wpath cpath inet proc exec tty unveil"
		execPromises = ""
	)
	pledge(promises, execPromises)

	configPath, err := getConfigPath()
	if err != nil {
		return err
	}
	unveil(configPath, "r")

	user, err := getUser(configPath)
	if err != nil {
		return fmt.Errorf("get user: %w", err)
	}

	// Ensure the server is available
	url := fmt.Sprint("http://127.0.0.1:", user.Port)
	if err = pingServer(url); err != nil {
		return err
	}

	// Attempt to use cached password before asking again
	user.Password, err = requestPasswordFromServer(user.Port, true)
	if err == nil {
		return nil
	}

	user.Password, err = requestPassword(-1, defaultPasswordPrompt)
	if err != nil {
		return fmt.Errorf("request password: %w", err)
	}

	// Verify the password before continuing
	if _, err = getKeys(configPath, user.Password); err != nil {
		return err
	}
	buf := bytes.NewBuffer(user.Password)
	resp, err := http.Post(url, "plaintext", buf)
	if err != nil {
		return fmt.Errorf("new request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != 200 {
		body, _ := ioutil.ReadAll(resp.Body)
		return fmt.Errorf("expected 200, got %d: %s", resp.StatusCode, body)
	}
	return nil
}

func copyFile(dst, src string) error {
	srcFi, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcFi.Close()

	// Create the destination file with the same permissions as the source
	// file
	srcStat, err := srcFi.Stat()
	if err != nil {
		return err
	}
	dstFi, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE, srcStat.Mode())
	if err != nil {
		return err
	}
	defer dstFi.Close()

	if _, err = io.Copy(dstFi, srcFi); err != nil {
		return fmt.Errorf("copy: %w", err)
	}
	return nil
}

func usage() {
	fmt.Println(`usage:

	shh [flags] [command]

global commands:
	init			initialize store or add self to existing store
	get $name		get secret
	set $name $val		set secret
	del $name		delete a secret
	copy $old $new          copy a secret, maintaining the same team access
	rename $old $new        rename a secret
	allow $user $secret	allow user access to a secret
	deny $user $secret	deny user access to a secret
	add-user $user $pubkey  add user to project given their public key
	rm-user $user		remove user from project
	search $regex		list all secrets containing the regex
	show [$user]		show user's allowed and denied keys
	edit			edit a secret using $EDITOR
	rotate			rotate key
	serve			start server to maintain password in memory
	login			login to server to maintain password in memory
	version			version information
	help			usage info

flags:
	-n			Non-interactive mode. Fail if shh would prompt for the password
	-f			shh filename. Defaults to .shh`)
}

func backupReminder(withConfig bool) {
	if withConfig {
		fmt.Println("> generated ~/.config/shh/config")
	}
	fmt.Println("> generated ~/.config/shh/id_rsa")
	fmt.Println("> generated ~/.config/shh/id_rsa.pub")
	fmt.Println(">")
	fmt.Println("> be sure to back up your ~/.config/shh/id_rsa and")
	fmt.Println("> remember your password, or you may lose access to your")
	fmt.Println("> secrets!")
}
