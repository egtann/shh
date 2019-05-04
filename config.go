package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	homedir "github.com/mitchellh/go-homedir"
	"github.com/pkg/errors"
)

type config struct {
	Username username
	Port     int
}

func getConfigPath() (string, error) {
	home, err := homedir.Dir()
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
				return nil, errors.Wrapf(err, "invalid port %s", parts[1])
			}
		default:
			return nil, fmt.Errorf("unknown part %s", parts[0])
		}
	}
	if err = scn.Err(); err != nil {
		return nil, errors.Wrap(err, "scan")
	}
	return conf, nil
}
