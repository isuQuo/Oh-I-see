package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"time"
)

var abuseIpdbUrl = "https://api.abuseipdb.com"

// Client is an AbuseIPDB client. Use NewClient() to instantiate.
type Client struct {
	http   *http.Client
	APIKey string
}

// NewClient initializes a new Client.
func NewClient(apiKey string) *Client {
	return &Client{
		http: &http.Client{
			Timeout: 60 * time.Second,
		},
		APIKey: apiKey,
	}
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

func (c *Client) CheckAbuseIpdb(ip string, days int) (AbuseIpDbCheckData, error) {
	if net.ParseIP(ip) == nil {
		return AbuseIpDbCheckData{}, fmt.Errorf("invalid IP: %s", ip)
	}

	url := fmt.Sprintf("%s/api/v2/check?ipAddress=%s&maxAgeInDays=%d&verbose=1", abuseIpdbUrl, ip, days)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Fatal(err)
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("Key", c.APIKey)

	resp, err := c.http.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return AbuseIpDbCheckData{}, err
	}

	// check if we've exceeded our limit
	err = checkAbuseIpdbRateLimit(body)
	if err != nil {
		return AbuseIpDbCheckData{}, err
	}

	response := AbuseIpDbCheckResponse{}
	json.Unmarshal(body, &response)

	return response.Data, err
}

func (c *Client) CheckVirusTotal(fileHash string) (VirusTotalResponse, error) {
	client := &http.Client{}

	req, err := http.NewRequest("GET", "https://www.virustotal.com/api/v3/files/"+fileHash, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("x-apikey", c.APIKey)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return VirusTotalResponse{}, nil
	}

	var report VirusTotalResponse
	err = json.NewDecoder(resp.Body).Decode(&report)
	if err != nil {
		return nil, err
	}

	return &report, nil
}
