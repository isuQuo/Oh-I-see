package abuseipdb

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

type AbuseIPDBClient struct {
	http   *http.Client
	APIKey string
}

func NewAbuseIPDBClient(apiKey string) *AbuseIPDBClient {
	return &AbuseIPDBClient{
		http: &http.Client{
			Timeout: 60 * time.Second,
		},
		APIKey: apiKey,
	}
}

func (c *AbuseIPDBClient) CheckIP(ip string) (interface{}, error) {
	if net.ParseIP(ip) == nil {
		return nil, fmt.Errorf("invalid IP: %s", ip)
	}

	url := fmt.Sprintf("https://api.abuseipdb.com/api/v2/check?ipAddress=%s&maxAgeInDays=90&verbose=1", ip)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("Key", c.APIKey)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// check if we've exceeded our limit
	err = checkAbuseIpdbRateLimit(body)
	if err != nil {
		return nil, err
	}

	response := AbuseIpDbCheckResponse{}
	json.Unmarshal(body, &response)

	return response, err
}

// Unable to implement
func (c *AbuseIPDBClient) CheckURL(url string) (interface{}, error) {
	return nil, errors.New("not implemented")
}

// Unable to implement
func (c *AbuseIPDBClient) CheckHash(hash string) (interface{}, error) {
	return nil, errors.New("not implemented")
}

func checkAbuseIpdbRateLimit(body []byte) error {
	rateLimit := AbuseIpDbRateLimit{}
	json.Unmarshal(body, &rateLimit)
	// we did not get any errors
	if len(rateLimit.Errors) == 0 {
		return nil
	}
	if rateLimit.Errors[0].Status == 0 {
		return errors.New("too many requests")
	}

	return nil
}
