package abuseipdb

import (
	"fmt"

	"github.com/isuQuo/OhISee/cmd/cli/datatypes"
)

type AbuseIpDbCheckResponse struct {
	Data AbuseIpDbCheckData `json:"data"`
}

type AbuseIpDbCheckData struct {
	IpAddress            string `json:"ipAddress"`
	IsPublic             bool   `json:"isPublic"`
	IpVersion            int    `json:"ipVersion"`
	IsWhitelisted        bool   `json:"isWhitelisted"`
	AbuseConfidenceScore int    `json:"abuseConfidenceScore"`
	CountryCode          string `json:"countryCode"`
	UsageType            string `json:"usageType"`
	Isp                  string `json:"isp"`
	Domain               string `json:"domain"`
	TotalReports         int    `json:"totalReports"`
	NumDistinctUsers     int    `json:"numDistinctUsers"`
	LastReportedAt       string `json:"lastReportedAt"`
}

//	type AbuseIpDbRateLimit struct {
//		RateLimit int `json:"X-Ratelimit-Remaining"`
//	}
type AbuseIpDbRateLimit struct {
	Errors []struct {
		Status int `json:"status"`
	} `json:"errors"`
}

func (c *AbuseIPDBClient) GetHeaders() []string {
	switch c.DataType {
	case datatypes.IP:
		return []string{"IP", "Abuse Confidence Score", "Country", "Usage Type", "ISP", "Domain", "Last Reported"}
	}

	return nil
}

func (c *AbuseIPDBClient) GetValues(ipInfo interface{}) []string {
	info := ipInfo.(AbuseIpDbCheckResponse)
	return []string{
		info.Data.IpAddress,
		fmt.Sprintf("%d", info.Data.AbuseConfidenceScore),
		info.Data.CountryCode,
		info.Data.UsageType,
		info.Data.Isp,
		info.Data.Domain,
		info.Data.LastReportedAt,
	}
}
