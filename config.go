package main

import (
	"encoding/json"
	"os"
)

type Configuration struct {
	DbUser     string
	DbPassword string
	DbName     string

	SecretKey string
}

func readConfig() (cfg Configuration, err error) {
	var file *os.File
	if file, err = os.Open("config.json"); err == nil {
		decoder := json.NewDecoder(file)
		err = decoder.Decode(&cfg)
	}

	return
}
