package provider

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
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

func (c *VirusTotalClient) GetHeaders() []string {
	return []string{"IP", "Type Description", "Type Tags", "Creation Date", "Names", "Last Modification Date", "Type Tag", "Times Submitted", "Total Votes Harmless", "Total Votes Malicious", "Size", "Suggested Threat Label", "Popular Threat Category", "Popular Threat Name", "Last Submission Date", "Meaningful Name", "SHA256", "Type Extension"}
}

func (c *VirusTotalClient) GetValues(ipInfo interface{}) []string {
	info := ipInfo.(VirusTotalResponse)
	attributes := info.Data.Attributes
	popularThreatCategory := ""
	if len(attributes.PopularThreatClassification.PopularThreatCategory) > 0 {
		popularThreatCategory = attributes.PopularThreatClassification.PopularThreatCategory[0].Value
	}
	popularThreatName := ""
	if len(attributes.PopularThreatClassification.PopularThreatName) > 0 {
		popularThreatName = attributes.PopularThreatClassification.PopularThreatName[0].Value
	}
	return []string{
		attributes.TypeDescription,
		strings.Join(attributes.TypeTags, ", "),
		time.Unix(attributes.CreationDate, 0).Format(time.RFC3339),
		strings.Join(attributes.Names, ", "),
		time.Unix(attributes.LastModificationDate, 0).Format(time.RFC3339),
		attributes.TypeTag,
		fmt.Sprintf("%d", attributes.TimesSubmitted),
		fmt.Sprintf("%d", attributes.TotalVotes.Harmless),
		fmt.Sprintf("%d", attributes.TotalVotes.Malicious),
		fmt.Sprintf("%d", attributes.Size),
		attributes.PopularThreatClassification.SuggestedThreatLabel,
		popularThreatCategory,
		popularThreatName,
		time.Unix(attributes.LastSubmissionDate, 0).Format(time.RFC3339),
		attributes.MeaningfulName,
		attributes.SHA256,
		attributes.TypeExtension,
	}
}
