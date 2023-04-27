package provider

import (
	"github.com/isuQuo/OhISee/cmd/cli/config"
	"github.com/isuQuo/OhISee/cmd/cli/provider/abuseipdb"
	"github.com/isuQuo/OhISee/cmd/cli/provider/virustotal"
)

type Provider interface {
	CheckIP(ip string) (interface{}, error)
	CheckURL(url string) (interface{}, error)
	CheckHash(hash string) (interface{}, error)

	GetHeaders() []string
	GetValues(info interface{}) []string
}

func GetProvider(method string, config *config.Configuration) Provider {
	switch method {
	case "abuseipdb":
		return abuseipdb.NewAbuseIPDBClient(config.AbuseIpdbAPIKey)
	case "vt":
		return virustotal.NewVirusTotalClient(config.VirusTotalAPIKey)
	default:
		return nil
	}
}
