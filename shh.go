package main

import (
	"encoding/json"
	"encoding/pem"
	"io"
	"os"

	"github.com/pkg/errors"
)

type Shh struct {
	file    string
	Secrets map[string]string     `json:"secrets"`
	Keys    map[string]*pem.Block `json:"keys"`
}

func NewShh() *Shh {
	return &Shh{
		Secrets: map[string]string{},
		Keys:    map[string]*pem.Block{},
	}
}

func ShhFromPath(pth string) (*Shh, error) {
	flags := os.O_CREATE | os.O_RDWR | os.O_TRUNC
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
