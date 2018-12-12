package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/pkg/errors"
)

type Config struct {
	Username Username
}

func ConfigFromPath(pth string) (*Config, error) {
	fi, err := os.Open(pth)
	if err != nil {
		return nil, errors.Wrap(err, "open")
	}
	defer fi.Close()
	config := &Config{}
	scn := bufio.NewScanner(fi)
	for scn.Scan() {
		line := scn.Text()
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		parts[0] = strings.TrimSpace(parts[0])
		parts[1] = strings.TrimSpace(parts[1])
		switch parts[0] {
		case "username":
			config.Username = Username(parts[1])
		default:
			return nil, fmt.Errorf("unknown part %s", parts[0])
		}
	}
	if err = scn.Err(); err != nil {
		return nil, errors.Wrap(err, "scan")
	}
	return config, nil
}
