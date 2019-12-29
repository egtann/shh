package main

import (
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

type shh struct {
	// Secrets maps users -> secret_labels -> secret_value. Each secret is
	// uniquely encrypted for each user given their public key.
	Secrets map[username]map[string]secret `json:"secrets"`

	// Keys are public keys used to encrypt secrets for each user.
	Keys map[username]*pem.Block `json:"keys"`

	// namespace to which all secret names are added. This prevents two
	// users creating their own secrets which have the same name but
	// resolve to different secrets.
	namespace map[string]struct{}

	// path of the .shh file itself.
	path string
}

type secret struct {
	AESKey    string `json:"key"`
	Encrypted string `json:"value"`
}

func newShh(path string) *shh {
	return &shh{
		Secrets:   map[username]map[string]secret{},
		Keys:      map[username]*pem.Block{},
		namespace: map[string]struct{}{},
		path:      path,
	}
}

// findShhRecursive checks for a file recursively up the filesystem until it
// hits an error.
func findShhRecursive(pth string) (string, error) {
	abs, err := filepath.Abs(pth)
	if err != nil {
		return "", fmt.Errorf("abs: %w", err)
	}
	if abs == string(filepath.Separator)+filepath.Base(pth) {
		// We hit the root, we're done
		return "", os.ErrNotExist
	}
	_, err = os.Stat(pth)
	switch {
	case os.IsNotExist(err):
		return findShhRecursive(filepath.Join("..", pth))
	case err != nil:
		return "", fmt.Errorf("stat: %w", err)
	}
	return pth, nil
}

func shhFromPath(pth string) (*shh, error) {
	recursivePath, err := findShhRecursive(pth)
	switch {
	case err == os.ErrNotExist:
		err = nil // Ignore error, keep going
	case err != nil:
		return nil, err
	}
	if recursivePath != "" {
		pth = recursivePath
	}
	flags := os.O_CREATE | os.O_RDWR
	fi, err := os.OpenFile(pth, flags, 0644)
	if err != nil {
		return nil, err
	}
	defer fi.Close()
	shh := newShh(pth)
	dec := json.NewDecoder(fi)
	err = dec.Decode(shh)
	switch {
	case err == io.EOF:
		// We newly created the file. Not an error, just an empty .shh
		return shh, nil
	case err != nil:
		return nil, fmt.Errorf("decode: %w", err)
	}
	for _, secrets := range shh.Secrets {
		for secretName := range secrets {
			shh.namespace[secretName] = struct{}{}
		}
	}
	return shh, nil
}

func (s *shh) EncodeToFile() error {
	flags := os.O_TRUNC | os.O_CREATE | os.O_WRONLY
	fi, err := os.OpenFile(s.path, flags, 0644)
	if err != nil {
		return err
	}
	defer fi.Close()
	return s.Encode(fi)
}

func (s *shh) Encode(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "\t")
	return enc.Encode(s)
}

// GetSecretsForUser. If there's an exact key match, the secret will be
// returned. If not, the "*" glob matches all secrets after the glob. If used,
// the glob must be the last character. This is supported: `staging/*` whereas
// this is not: `staging/*/database_url` (this returns an error). This function
// only returns nil alongside an error. It may return an empty slice.
func (s *shh) GetSecretsForUser(key string, user username) (map[string]secret, error) {
	if key == "" {
		return nil, errors.New("empty key")
	}
	if user == "" {
		return nil, errors.New("empty user")
	}
	userSecrets, exist := s.Secrets[user]
	if !exist {
		s.Secrets[user] = map[string]secret{}
	}
	sec, exist := userSecrets[key]
	if exist {
		tmp, err := base64.StdEncoding.DecodeString(sec.AESKey)
		if err != nil {
			return nil, fmt.Errorf("decode b64 aes key: %w", err)
		}
		sec.AESKey = string(tmp)
		tmp, err = base64.StdEncoding.DecodeString(sec.Encrypted)
		if err != nil {
			return nil, fmt.Errorf("decode b64 secret: %w", err)
		}
		sec.Encrypted = string(tmp)
		return map[string]secret{key: sec}, nil
	}
	glob := strings.Index(key, "*")
	if glob == -1 {
		return nil, errors.New("no secret found")
	}
	if glob < len(key)-1 {
		return nil, errors.New("invalid glob: must be last character")
	}
	key = key[:len(key)-1]
	matches := map[string]secret{}
	for k, v := range userSecrets {
		match := strings.HasPrefix(k, key)
		if match {
			byt, err := base64.StdEncoding.DecodeString(v.AESKey)
			if err != nil {
				return nil, fmt.Errorf("decode b64 aes key: %w", err)
			}
			v.AESKey = string(byt)
			byt, err = base64.StdEncoding.DecodeString(v.Encrypted)
			if err != nil {
				return nil, fmt.Errorf("decode b64 encrypted: %w", err)
			}
			v.Encrypted = string(byt)
			matches[k] = v
		}
	}
	return matches, nil
}

func (s *shh) AllSecrets() []string {
	seen := map[string]struct{}{}
	for _, userSecrets := range s.Secrets {
		for name := range userSecrets {
			seen[name] = struct{}{}
		}
	}
	secrets := []string{}
	for name := range seen {
		secrets = append(secrets, name)
	}
	return secrets
}
