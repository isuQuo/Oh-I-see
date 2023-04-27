package virustotal

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"
)

type VirusTotalClient struct {
	http   *http.Client
	APIKey string
}

func NewVirusTotalClient(apiKey string) *VirusTotalClient {
	return &VirusTotalClient{
		http: &http.Client{
			Timeout: 60 * time.Second,
		},
		APIKey: apiKey,
	}
}

// Not yet implemented
func (c *VirusTotalClient) CheckIP(ip string) (interface{}, error) {
	return nil, errors.New("not implemented")
	/* req, err := http.NewRequest("GET", "https://www.virustotal.com/api/v3/ip_addresses/"+ip, nil)
	if err != nil {
		return VirusTotalResponse{}, err
	}

	req.Header.Set("x-apikey", c.APIKey)
	resp, err := c.http.Do(req)
	if err != nil {
		return VirusTotalResponse{}, err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return VirusTotalResponse{}, fmt.Errorf("request failed with status code %d", resp.StatusCode)
	}

	var report VirusTotalResponse
	err = json.NewDecoder(resp.Body).Decode(&report)
	if err != nil {
		return VirusTotalResponse{}, err
	}

	return report, nil */
}

// Not yet implemented
func (c *VirusTotalClient) CheckURL(url string) (interface{}, error) {
	return nil, errors.New("not implemented")
	/* req, err := http.NewRequest("GET", "https://www.virustotal.com/api/v3/urls/"+url, nil)
	if err != nil {
		return VirusTotalResponse{}, err
	}

	req.Header.Set("x-apikey", c.APIKey)
	resp, err := c.http.Do(req)
	if err != nil {
		return VirusTotalResponse{}, err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return VirusTotalResponse{}, fmt.Errorf("request failed with status code %d", resp.StatusCode)
	}

	var report VirusTotalResponse
	err = json.NewDecoder(resp.Body).Decode(&report)
	if err != nil {
		return VirusTotalResponse{}, err
	}

	return report, nil */
}

func (c *VirusTotalClient) CheckHash(hash string) (interface{}, error) {
	req, err := http.NewRequest("GET", "https://www.virustotal.com/api/v3/files/"+hash, nil)
	if err != nil {
		return VirusTotalResponse{}, err
	}

	req.Header.Set("x-apikey", c.APIKey)
	resp, err := c.http.Do(req)
	if err != nil {
		return VirusTotalResponse{}, err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return VirusTotalResponse{}, fmt.Errorf("request failed with status code %d", resp.StatusCode)
	}

	var report VirusTotalResponse
	err = json.NewDecoder(resp.Body).Decode(&report)
	if err != nil {
		return VirusTotalResponse{}, err
	}

	return report, nil
}
