package main

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Addr        string            `yaml:"addr"`
	Salt        string            `yaml:"salt"`
	Secret      string            `yaml:"secret`
	MockedUsers map[string]string `yaml:"mocked_users"`
}

func readConfig(fileName string) (*Config, error) {
	file, err := os.Open(fileName)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	config := &Config{}
	err = yaml.NewDecoder(file).Decode(config)
	if err != nil {
		return nil, fmt.Errorf("failed to decode: %w", err)
	}

	return config, nil
}
