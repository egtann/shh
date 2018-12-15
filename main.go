package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"github.com/pkg/errors"
)

var serverBooted bool

func main() {
	err := run()
	if err != nil {
		switch err.(type) {
		case emptyArgError:
			usage()
		default:
			fmt.Println("error: " + err.Error())
		}
		os.Exit(1)
	}
}

func run() error {
	flag.Parse()
	arg, tail := parseArg(flag.Args())
	if arg == "" {
		return emptyArgError{}
	}

	// Enforce that a .shh file exists for anything for most commands
	switch arg {
	case "init", "gen-keys": // Do nothing
	default:
		_, err := os.Stat(".shh")
		if os.IsNotExist(err) {
			return errors.New("missing .shh, run `shh init`")
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
		return initShh()
	case "gen-keys":
		return genKeys(tail)
	case "get":
		return get(tail)
	case "set":
		return set(tail)
	case "del":
		return del(tail)
	case "edit":
		return edit(tail)
	case "allow":
		return allow(tail)
	case "deny":
		return deny(tail)
	case "add-user":
		return addUser(tail)
	case "rm-user":
		return rmUser(tail)
	case "rotate":
		return rotate(tail)
	case "serve":
		return serve(tail)
	case "login":
		return login(tail)
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

// genKeys for self in ~/.config/shh.
func genKeys(args []string) error {
	if len(args) > 0 {
		return errors.New("bad args: expected none")
	}
	configPath, err := getConfigPath()
	if err != nil {
		return err
	}
	_, err = ConfigFromPath(configPath)
	if err == nil {
		return errors.New("keys exist at ~/.config/shh, run `shh rotate` to change keys")
	}
	if _, err = createUser(configPath); err != nil {
		return err
	}
	backupReminder(true)
	return nil
}

// initShh creates your project file ".shh". If the project file already
// exists or if keys have not been generated, initShh reports an error.
func initShh() error {
	if _, err := os.Stat(".shh"); err == nil {
		return errors.New(".shh already exists")
	}
	configPath, err := getConfigPath()
	if err != nil {
		return err
	}
	user, err := getUser(configPath)
	if err != nil {
		return errors.Wrap(err, "get user")
	}
	shh, err := ShhFromPath(".shh")
	if err != nil {
		return errors.Wrap(err, "shh from path")
	}
	shh.Keys[user.Username] = user.Keys.PublicKeyBlock
	return shh.EncodeToPath(".shh")
}

// TODO enforce 600 permissions on id_rsa file and .shh when any command is run

// get a secret value by name.
func get(args []string) error {
	if len(args) != 1 {
		return errors.New("bad args: expected `get $name`")
	}
	secretName := args[0]
	configPath, err := getConfigPath()
	if err != nil {
		return err
	}
	user, err := getUser(configPath)
	if err != nil {
		return errors.Wrap(err, "get user")
	}
	shh, err := ShhFromPath(".shh")
	if err != nil {
		return err
	}
	secrets, err := shh.GetSecretsForUser(secretName, user.Username)
	if err != nil {
		return err
	}
	user.Password, err = requestPassword(user.Port, "", false)
	if err != nil {
		return err
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
			return errors.Wrap(err, "decrypt secret")
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
		fmt.Println(string(plaintext))
	}
	return nil
}

// set a secret value.
func set(args []string) error {
	if len(args) != 2 {
		return errors.New("bad args: expected `set $name $val`")
	}
	configPath, err := getConfigPath()
	if err != nil {
		return err
	}
	user, err := getUser(configPath)
	if err != nil {
		return err
	}
	shh, err := ShhFromPath(".shh")
	if err != nil {
		return err
	}
	if _, exist := shh.Secrets[user.Username]; !exist {
		shh.Secrets[user.Username] = map[string]Secret{}
	}
	keys, err := getPublicKey(configPath)
	if err != nil {
		return errors.Wrap(err, "get public key")
	}

	// Encrypt the secret using an AES key
	aesKey := make([]byte, 32)
	if _, err := rand.Read(aesKey); err != nil {
		return errors.Wrap(err, "read aes key")
	}
	aesBlock, err := aes.NewCipher(aesKey)
	if err != nil {
		return errors.Wrap(err, "new aes cipher")
	}
	plaintext := args[1]
	encrypted := make([]byte, aes.BlockSize+len(plaintext))
	iv := encrypted[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return errors.Wrap(err, "read iv")
	}
	stream := cipher.NewCFBEncrypter(aesBlock, iv)
	stream.XORKeyStream(encrypted[aes.BlockSize:], []byte(plaintext))

	// Encrypt the AES key using the private RSA key
	aesKey, err = rsa.EncryptOAEP(sha256.New(), rand.Reader,
		keys.PublicKey, []byte(aesKey), nil)
	if err != nil {
		return errors.Wrap(err, "encrypt aes key")
	}
	sec := Secret{
		AESKey:    base64.StdEncoding.EncodeToString(aesKey),
		Encrypted: base64.StdEncoding.EncodeToString(encrypted),
	}
	shh.Secrets[user.Username][args[0]] = sec
	err = shh.EncodeToPath(".shh")
	return errors.Wrap(err, "encode to path")
}

// del deletes a secret for all users.
func del(args []string) error {
	if len(args) != 1 {
		return errors.New("bad args: expected `del $secret`")
	}
	secret := args[0]
	configPath, err := getConfigPath()
	if err != nil {
		return err
	}
	user, err := getUser(configPath)
	if err != nil {
		return err
	}
	shh, err := ShhFromPath(".shh")
	if err != nil {
		return err
	}
	secrets, err := shh.GetSecretsForUser(secret, user.Username)
	if err != nil {
		return err
	}
	userSecrets := shh.Secrets[user.Username]
	for key := range secrets {
		delete(userSecrets, key)
	}
	if len(userSecrets) == 0 {
		delete(shh.Secrets, user.Username)
	}
	err = shh.EncodeToPath(".shh")
	return errors.Wrap(err, "encode to path")
}

// allow a user to access a secret. You must have access yourself.
//
// TODO allow all using "$user *" syntax.
func allow(args []string) error {
	if len(args) != 2 {
		return errors.New("bad args: expected `allow $user $secret`")
	}
	username := Username(args[0])
	secretKey := args[1]
	configPath, err := getConfigPath()
	if err != nil {
		return errors.Wrap(err, "get config path")
	}
	user, err := getUser(configPath)
	if err != nil {
		return errors.Wrap(err, "get user")
	}
	shh, err := ShhFromPath(".shh")
	if err != nil {
		return err
	}
	block, exist := shh.Keys[username]
	if !exist {
		return fmt.Errorf("%q is not a user in the project. try `shh add-user %s $PUBKEY`", username, username)
	}
	pubKey, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		return errors.Wrap(err, "parse public key")
	}

	// Decrypt all matching secrets
	user.Password, err = requestPassword(user.Port, "", false)
	if err != nil {
		return err
	}
	keys, err := getKeys(configPath, user.Password)
	if err != nil {
		return errors.Wrap(err, "get keys")
	}
	secrets, err := shh.GetSecretsForUser(secretKey, user.Username)
	if err != nil {
		return err
	}
	if len(secrets) == 0 {
		return errors.New("no matching secrets which you can access")
	}
	if _, exist := shh.Secrets[username]; !exist {
		shh.Secrets[username] = map[string]Secret{}
	}
	for key, secret := range secrets {
		// Decrypt AES key using personal RSA key
		aesKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader,
			keys.PrivateKey, []byte(secret.AESKey), nil)
		if err != nil {
			return errors.Wrap(err, "decrypt secret")
		}
		aesBlock, err := aes.NewCipher(aesKey)
		if err != nil {
			return err
		}
		ciphertext := []byte(secret.Encrypted)
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

		// Encrypt the secret using the new AES key
		encrypted := make([]byte, aes.BlockSize+len(plaintext))
		iv = encrypted[:aes.BlockSize]
		if _, err := io.ReadFull(rand.Reader, iv); err != nil {
			return errors.Wrap(err, "read iv")
		}
		stream = cipher.NewCFBEncrypter(aesBlock, iv)
		stream.XORKeyStream(encrypted[aes.BlockSize:], []byte(plaintext))

		// Encrypt the secret using that AES key
		aesBlock, err = aes.NewCipher(aesKey)
		if err != nil {
			return err
		}

		// Encrypt the AES key using the public key
		encryptedAES, err := rsa.EncryptOAEP(sha256.New(), rand.Reader,
			pubKey, aesKey, nil)
		if err != nil {
			return errors.Wrap(err, "reencrypt secret")
		}

		// We base64 encode all encrypted data before passing it into
		// the .shh file
		sec := Secret{
			AESKey:    base64.StdEncoding.EncodeToString(encryptedAES),
			Encrypted: base64.StdEncoding.EncodeToString(encrypted),
		}

		// Add encrypted data and key to .shh
		shh.Secrets[username][key] = sec
	}
	return shh.EncodeToPath(".shh")
}

// deny a user from accessing secrets.
func deny(args []string) error {
	if len(args) > 2 {
		return errors.New("bad args: expected `deny $user [$secret]`")
	}
	var secretKey string
	if len(args) == 1 {
		secretKey = "*"
	} else {
		secretKey = args[1]
	}
	username := Username(args[0])
	shh, err := ShhFromPath(".shh")
	if err != nil {
		return err
	}
	secrets, err := shh.GetSecretsForUser(secretKey, username)
	if err != nil {
		return errors.Wrap(err, "get secrets for user")
	}
	userSecrets := shh.Secrets[username]
	for key := range secrets {
		delete(userSecrets, key)
	}
	if len(userSecrets) == 0 {
		delete(shh.Secrets, username)
	}
	return shh.EncodeToPath(".shh")
}

// show

// edit a secret using $EDITOR.
func edit(args []string) error {
	if len(args) > 1 {
		return errors.New("bad args: expected `edit $secret`")
	}
	configPath, err := getConfigPath()
	if err != nil {
		return err
	}
	user, err := getUser(configPath)
	if err != nil {
		return errors.Wrap(err, "get user")
	}
	user.Password, err = requestPassword(user.Port, "", false)
	if err != nil {
		return err
	}
	keys, err := getKeys(configPath, user.Password)
	if err != nil {
		return err
	}
	shh, err := ShhFromPath(".shh")
	if err != nil {
		return err
	}
	secrets, err := shh.GetSecretsForUser(args[0], user.Username)
	if err != nil {
		return err
	}
	if len(secrets) > 1 {
		return errors.New("mulitple secrets found, cannot use *")
	}

	// Create tmp file
	fi, err := ioutil.TempFile("", "shh")
	if err != nil {
		return errors.Wrap(err, "temp file")
	}
	defer fi.Close()

	// Copy decrypted secret into tmp file
	var plaintext, aesKey []byte
	var key string
	var secret Secret
	for k, sec := range secrets {
		key = k
		secret = sec

		// Decrypt the AES key using the private key
		aesKey, err = rsa.DecryptOAEP(sha256.New(), rand.Reader,
			keys.PrivateKey, []byte(sec.AESKey), nil)
		if err != nil {
			return errors.Wrap(err, "decrypt secret")
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
	io.Copy(fi, bytes.NewReader(plaintext))

	// Open tmp file in vim
	cmd := exec.Command("bash", "-c", "$EDITOR "+fi.Name())
	cmd.Stdout = os.Stdout
	cmd.Stdin = os.Stdin
	if err = cmd.Start(); err != nil {
		return errors.Wrap(err, "cmd")
	}
	if err = cmd.Wait(); err != nil {
		return errors.Wrap(err, "wait")
	}

	// Re-encrypt content
	aesBlock, err := aes.NewCipher(aesKey)
	if err != nil {
		return errors.Wrap(err, "new aes cipher")
	}
	plaintext, err = ioutil.ReadFile(fi.Name())
	if err != nil {
		return errors.Wrap(err, "read all")
	}
	encrypted := make([]byte, aes.BlockSize+len(plaintext))
	iv := encrypted[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return errors.Wrap(err, "read iv")
	}
	stream := cipher.NewCFBEncrypter(aesBlock, iv)
	stream.XORKeyStream(encrypted[aes.BlockSize:], []byte(plaintext))

	// Re-write the project file with the updated secret
	shh.Secrets[user.Username][key] = Secret{
		AESKey:    base64.StdEncoding.EncodeToString([]byte(secret.AESKey)),
		Encrypted: base64.StdEncoding.EncodeToString(encrypted),
	}
	return shh.EncodeToPath(".shh")
}

// rotate generates new keys and re-encrypts all secrets using the new keys.
// You should also use this to change your password.
func rotate(args []string) error {
	if len(args) > 0 {
		return errors.New("bad args: expected none")
	}

	// Allow changing the password
	oldPass, err := requestPassword(-1, "old password", false)
	if err != nil {
		return errors.Wrap(err, "request old password")
	}
	newPass, err := requestPassword(-1, "new password", true)
	if err != nil {
		return errors.Wrap(err, "request new password")
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
		return errors.Wrap(err, "make tmp dir")
	}
	defer func() {
		os.RemoveAll(tmpDir)
	}()

	keys, err := createKeys(tmpDir, newPass)
	if err != nil {
		return errors.Wrap(err, "create keys")
	}
	user, err := getUser(configPath)
	if err != nil {
		return errors.Wrap(err, "get user")
	}

	// Decrypt all AES secrets for user, re-encrypt with new key
	oldKeys, err := getKeys(configPath, oldPass)
	if err != nil {
		return err
	}
	shh, err := ShhFromPath(".shh")
	if err != nil {
		return err
	}
	secrets := shh.Secrets[user.Username]
	for key, secret := range secrets {
		// Decrypt AES key using old key
		byt, err := base64.StdEncoding.DecodeString(secret.AESKey)
		if err != nil {
			return errors.Wrap(err, "decode base64")
		}
		aesKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader,
			oldKeys.PrivateKey, byt, nil)
		if err != nil {
			return errors.Wrap(err, "decrypt secret")
		}

		// Re-encrypt using new public key
		encryptedAES, err := rsa.EncryptOAEP(sha256.New(), rand.Reader,
			keys.PublicKey, aesKey, nil)
		if err != nil {
			return errors.Wrap(err, "reencrypt secret")
		}
		shh.Secrets[user.Username][key] = Secret{
			AESKey:    base64.StdEncoding.EncodeToString(encryptedAES),
			Encrypted: secret.Encrypted,
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
		return errors.Wrap(err, "back up id_rsa")
	}
	err = copyFile(
		filepath.Join(configPath, "id_rsa.pub.bak"),
		filepath.Join(configPath, "id_rsa.pub"),
	)
	if err != nil {
		return errors.Wrap(err, "back up id_rsa.pub")
	}

	// Rewrite the project file to use the new public key
	if err = shh.EncodeToPath(".shh"); err != nil {
		return errors.Wrap(err, "encode .shh")
	}

	// Move new keys on top of current keys in the filesystem
	err = os.Rename(
		filepath.Join(tmpDir, "id_rsa"),
		filepath.Join(configPath, "id_rsa"),
	)
	if err != nil {
		return errors.Wrap(err, "replace id_rsa")
	}
	err = os.Rename(
		filepath.Join(tmpDir, "id_rsa.pub"),
		filepath.Join(configPath, "id_rsa.pub"),
	)
	if err != nil {
		return errors.Wrap(err, "replace id_rsa.pub")
	}

	// Delete our backed up keys
	err = os.Remove(filepath.Join(configPath, "id_rsa.bak"))
	if err != nil {
		return errors.Wrap(err, "delete id_rsa.bak")
	}
	err = os.Remove(filepath.Join(configPath, "id_rsa.pub.bak"))
	if err != nil {
		return errors.Wrap(err, "delete id_rsa.pub.bak")
	}
	backupReminder(false)
	return nil
}

// addUser to project file.
func addUser(args []string) error {
	if len(args) != 0 && len(args) != 2 {
		return errors.New("bad args: expected `add-user [$user $pubkey]`")
	}
	shh, err := ShhFromPath(".shh")
	if err != nil {
		return err
	}
	var user *User
	if len(args) == 0 {
		// Default to self
		configPath, err := getConfigPath()
		if err != nil {
			return err
		}
		user, err = getUser(configPath)
		if err != nil {
			return errors.Wrap(err, "get user")
		}
	} else {
		user = &User{Username: Username(args[0])}
	}
	if _, exist := shh.Keys[user.Username]; exist {
		return nil
	}
	if len(args) == 0 {
		shh.Keys[user.Username] = user.Keys.PublicKeyBlock
	} else {
		shh.Keys[user.Username], _ = pem.Decode([]byte(args[1]))
	}
	return shh.EncodeToPath(".shh")
}

// rmUser from project file.
func rmUser(args []string) error {
	if len(args) != 1 {
		return errors.New("bad args: expected `rm-user $user`")
	}
	shh, err := ShhFromPath(".shh")
	if err != nil {
		return err
	}
	username := Username(args[0])
	if _, exist := shh.Keys[username]; !exist {
		return errors.New("user not found")
	}
	delete(shh.Keys, username)
	delete(shh.Secrets, username)
	return shh.EncodeToPath(".shh")
}

// serve maintains the password in memory for an hour.
func serve(args []string) error {
	if len(args) > 0 {
		return errors.New("bad args: expected none")
	}
	configPath, err := getConfigPath()
	if err != nil {
		return err
	}
	user, err := getUser(configPath)
	if err != nil {
		return errors.Wrap(err, "get user")
	}
	var mu sync.Mutex
	password := ""
	if !serverBooted {
		serverBooted = true
		go func() {
			// TODO reset timer on each login
			for range time.Tick(time.Hour) {
				mu.Lock()
				password = ""
				mu.Unlock()
			}
		}()
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			w.Write([]byte(password))
			return
		}
		byt, err := ioutil.ReadAll(r.Body)
		if len(byt) == 0 && err == nil {
			err = errors.New("empty body")
		}
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(err.Error()))
			return
		}
		mu.Lock()
		password = string(byt)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	})
	return http.ListenAndServe(fmt.Sprint(":", user.Port), mux)
}

// login to the server, caching the password in memory for 1 hour.
func login(args []string) error {
	if len(args) > 0 {
		return errors.New("bad args: expected none")
	}
	configPath, err := getConfigPath()
	if err != nil {
		return err
	}
	user, err := getUser(configPath)
	if err != nil {
		return errors.Wrap(err, "get user")
	}
	user.Password, err = requestPassword(-1, "", false)
	if err != nil {
		return errors.Wrap(err, "request password")
	}

	// Verify the password before continuing
	if _, err = getKeys(configPath, user.Password); err != nil {
		return err
	}

	buf := bytes.NewBuffer(user.Password)
	resp, err := http.Post(fmt.Sprint("http://127.0.0.1:", user.Port), "plaintext", buf)
	if err != nil {
		return errors.Wrap(err, "new request")
	}
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

	io.Copy(dstFi, srcFi)
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
	allow $user $secret	allow user access to a secret
	deny $user $secret	deny user access to a secret
	add-user $user $pubkey  add user to project given their public key
	rm-user $user		remove user from project
	show [$user]		show user's allowed and denied keys
	edit			edit a secret using $EDITOR
	rotate			rotate key
	serve			start server to maintain password in memory
	login			login to server to maintain password in memory
`)
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
