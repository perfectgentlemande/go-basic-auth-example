package main

import (
	"fmt"
	"os"

	"github.com/perfectgentlemande/go-basic-auth-example/internal/service"
	"gopkg.in/yaml.v3"
)

type Config struct {
	Addr    string          `yaml:"addr"`
	Service *service.Config `yaml:"service"`
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
