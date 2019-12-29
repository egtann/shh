package main

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type config struct {
	Username username
	Port     int
}

func getConfigPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config", "shh"), nil
}

func configFromPath(pth string) (*config, error) {
	pth = filepath.Join(pth, "config")
	fi, err := os.Open(pth)
	if os.IsNotExist(err) {
		return nil, errors.New("missing keys. run `shh gen-keys`")
	}
	if err != nil {
		return nil, err
	}
	defer fi.Close()
	conf := &config{}
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
			conf.Username = username(parts[1])
		case "port":
			conf.Port, err = strconv.Atoi(parts[1])
			if err != nil {
				return nil, fmt.Errorf("invalid port %s: %w", parts[1], err)
			}
		default:
			return nil, fmt.Errorf("unknown part %s", parts[0])
		}
	}
	if err = scn.Err(); err != nil {
		return nil, fmt.Errorf("scan: %w", err)
	}
	return conf, nil
}
