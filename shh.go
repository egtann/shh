package main

import (
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"os"
	"strings"

	"github.com/pkg/errors"
)

type Shh struct {
	file string

	// Secrets maps users -> secret_labels -> secret_value. Each secret is
	// uniquely encrypted for each user given their public key.
	Secrets map[Username]map[string]Secret `json:"secrets"`

	// Keys are public keys used to encrypt secrets for each user.
	Keys map[Username]*pem.Block `json:"keys"`
}

type Secret struct {
	AESKey    string `json:"key"`
	Encrypted string `json:"value"`
}

func NewShh() *Shh {
	return &Shh{
		Secrets: map[Username]map[string]Secret{},
		Keys:    map[Username]*pem.Block{},
	}
}

func ShhFromPath(pth string) (*Shh, error) {
	flags := os.O_CREATE | os.O_RDWR
	fi, err := os.OpenFile(pth, flags, 0644)
	if err != nil {
		return nil, err
	}
	defer fi.Close()
	shh := NewShh()
	dec := json.NewDecoder(fi)
	err = dec.Decode(shh)
	if err == io.EOF {
		// We newly created the file. Not an error, just an empty .shh
		return shh, nil
	}
	return shh, errors.Wrap(err, "decode")
}

func (s *Shh) EncodeToPath(pth string) error {
	flags := os.O_TRUNC | os.O_CREATE | os.O_WRONLY
	fi, err := os.OpenFile(pth, flags, 0644)
	if err != nil {
		return err
	}
	defer fi.Close()
	return s.Encode(fi)
}

func (s *Shh) Encode(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "\t")
	return enc.Encode(s)
}

// GetSecretsForUser. If there's an exact key match, the secret will be
// returned.  If not, the "*" glob matches all secrets after the glob. If used,
// the glob must be the last character. This is supported: `staging/*` whereas
// this is not: `staging/*/database_url` (this returns an error). This function
// only returns nil alongside an error. It may return an empty slice.
func (s *Shh) GetSecretsForUser(key string, user Username) (map[string]Secret, error) {
	if key == "" {
		return nil, errors.New("empty key")
	}
	if user == "" {
		return nil, errors.New("empty user")
	}
	userSecrets, exist := s.Secrets[user]
	if !exist {
		s.Secrets[user] = map[string]Secret{}
	}
	secret, exist := userSecrets[key]
	if exist {
		tmp, err := base64.StdEncoding.DecodeString(secret.AESKey)
		if err != nil {
			return nil, errors.Wrap(err, "decode base64 aes key")
		}
		secret.AESKey = string(tmp)
		tmp, err = base64.StdEncoding.DecodeString(secret.Encrypted)
		if err != nil {
			return nil, errors.Wrap(err, "decode base64 secret")
		}
		secret.Encrypted = string(tmp)
		return map[string]Secret{key: secret}, nil
	}
	glob := strings.Index(key, "*")
	if glob == -1 {
		return nil, errors.New("no secret found")
	}
	if glob < len(key)-1 {
		return nil, errors.New("invalid glob: must be last character")
	}
	key = key[:len(key)-1]
	matches := map[string]Secret{}
	for k, v := range userSecrets {
		match := strings.HasPrefix(k, key)
		if match {
			byt, err := base64.StdEncoding.DecodeString(v.AESKey)
			if err != nil {
				return nil, errors.Wrap(err, "decode base64 aes key")
			}
			v.AESKey = string(byt)
			byt, err = base64.StdEncoding.DecodeString(v.Encrypted)
			if err != nil {
				return nil, errors.Wrap(err, "decode base64 encrypted")
			}
			v.Encrypted = string(byt)
			matches[k] = v
		}
	}
	return matches, nil
}
