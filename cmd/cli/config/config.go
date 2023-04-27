package config

import (
	"encoding/json"
	"log"
	"os"
)

type Configuration struct {
	AbuseIpdbAPIKey  string `json:"AbuseIpdbAPIKey"`
	VirusTotalAPIKey string `json:"VirusTotalAPIKey"`
}

func LoadConfig() *Configuration {
	f, _ := os.Open("conf.json")

	decoder := json.NewDecoder(f)
	configuration := Configuration{}
	err := decoder.Decode(&configuration)
	if err != nil {
		log.Fatal(err)
	}

	defer f.Close()
	return &configuration
}
