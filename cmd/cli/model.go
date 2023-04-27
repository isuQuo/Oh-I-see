package main

import (
	"fmt"
	"reflect"
)

type Configuration struct {
	AbuseIpdbAPIKey  string `json:"AbuseIpdbAPIKey"`
	VirusTotalAPIKey string `json:"VirusTotalAPIKey"`
}

type VirusTotalResponse struct {
	Data Data `json:"data"`
}

type Data struct {
	Attributes VirusTotalAttributes `json:"attributes"`
}

type VirusTotalAttributes struct {
	TypeDescription             string                 `json:"type_description"`
	TypeTags                    []string               `json:"type_tags"`
	CreationDate                int64                  `json:"creation_date"`
	Names                       []string               `json:"names"`
	LastModificationDate        int64                  `json:"last_modification_date"`
	TypeTag                     string                 `json:"type_tag"`
	TimesSubmitted              int                    `json:"times_submitted"`
	TotalVotes                  TotalVotes             `json:"total_votes"`
	Size                        int64                  `json:"size"`
	PopularThreatClassification PopularThreat          `json:"popular_threat_classification"`
	LastSubmissionDate          int64                  `json:"last_submission_date"`
	MeaningfulName              string                 `json:"meaningful_name"`
	SandboxVerdicts             map[string]interface{} `json:"sandbox_verdicts"`
	SHA256                      string                 `json:"sha256"`
	TypeExtension               string                 `json:"type_extension"`
}

type TotalVotes struct {
	Harmless  int `json:"harmless"`
	Malicious int `json:"malicious"`
}

type PopularThreat struct {
	SuggestedThreatLabel  string        `json:"suggested_threat_label"`
	PopularThreatCategory []ThreatCount `json:"popular_threat_category"`
	PopularThreatName     []ThreatCount `json:"popular_threat_name"`
}

type ThreatCount struct {
	Count int    `json:"count"`
	Value string `json:"value"`
}

// model json data
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

func GetHeaders(class interface{}) []string {
	v := reflect.ValueOf(class)
	if v.Kind() == reflect.Ptr {
		v = v.Elem() // Get the underlying struct value if it's a pointer
	}

	typeOfV := v.Type()

	values := make([]string, v.NumField())

	for i := range values {
		values[i] = typeOfV.Field(i).Name
	}

	return values
}

// convert to csv format
func GetValues(info interface{}) []string {
	v := reflect.ValueOf(info)

	// If the input is a pointer, extract the underlying value
	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}

	// Ensure the input is a struct
	if v.Kind() != reflect.Struct {
		panic("GetValues: input must be a struct or a pointer to a struct")
	}

	var values []string

	for i := 0; i < v.NumField(); i++ {
		values = append(values, fmt.Sprintf("%+v", v.Field(i).Interface()))
	}

	return values
}
