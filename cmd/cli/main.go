package main

import (
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"
	"time"
)

var method string

func main() {
	availableMethods := []string{"abuseipdb", "vt"}
	availableExports := []string{"csv", "json"}

	inputFile := flag.String(
		"in", "", "input file. List of IPs separated by newlines",
	)
	outputFile := flag.String(
		"out", "", fmt.Sprintf("output file. Choices are %s", availableExports),
	)
	checkMethod := flag.String(
		"method", "", fmt.Sprintf("Choices are %s", availableMethods),
	)
	flag.Parse()

	if !checkMethods(*checkMethod, availableMethods) {
		log.Fatalf("Choices are %s", availableMethods)
	}
	method = *checkMethod

	content := readFile(*inputFile)
	ipSlice := generateIpSlice(content)

	// test if our export should be in csv or json
	if strings.Contains(*outputFile, ".csv") {
		toCsv(ipSlice, outputFile)
	} else if strings.Contains(*outputFile, ".json") {
		toJson(ipSlice, outputFile)
	} else {
		log.Fatal("invalid export choice")
	}

}

func getConfig() string {
	f, _ := os.Open("conf.json")

	decoder := json.NewDecoder(f)
	configuration := Configuration{}
	err := decoder.Decode(&configuration)
	if err != nil {
		log.Fatal(err)
	}

	defer f.Close()
	switch method {
	case "abuseipdb":
		return configuration.AbuseIpdbAPIKey
	case "vt":
		return configuration.VirusTotalAPIKey
	}

	return ""
}

func checkMethods(method string, availableMethods []string) bool {
	set := make(map[string]struct{}, len(availableMethods))
	for _, s := range availableMethods {
		set[s] = struct{}{}
	}

	_, ok := set[method]
	return ok
}

func readFile(fileName string) []byte {
	content, err := os.ReadFile(fileName)
	if err != nil {
		log.Fatal(err)
	}

	return content
}

func generateIpSlice(fileContent []byte) []string {
	re := regexp.MustCompile(`^(?:https?:\/\/)?(?:[^@\/\n]+@)?(?:www\.)?([^:\/?\n]+)`)
	ipSlice := strings.Split(string(fileContent), "\r\n")

	// create a set to remove duplicates
	set := make(map[string]struct{}, len(ipSlice))
	for _, entry := range ipSlice {
		if entry != "" {
			match := re.FindStringSubmatch(string(entry))
			set[match[1]] = struct{}{}
		}
	}

	var entries []string
	for entry := range set {
		entries = append(entries, entry)
	}

	return entries
}

func getIpInfo(ip string) (interface{}, error) {
	key := getConfig()
	if key == "" {
		log.Fatalf("API Key not found for %s", method)
	}

	switch method {
	case "abuseipdb":
		client := client.NewClient(key)
		report, err := client.CheckAbuseIpdb(ip, 90)
		if err != nil {
			return nil, err
		}
		return report, nil

	case "vt":
		client := client.NewClient(key)
		report, err := client.CheckVirusTotal(ip)
		if err != nil {
			return nil, err
		}
		time.Sleep(15 * time.Second)
		return report, nil
	}

	return nil, nil
}

func toCsv(entries []string, out *string) {
	// get struct headers for chosen method
	var headers []string

	switch method {
	case "abuseipdb":
		headers = GetHeaders(AbuseIpDbCheckData{})
	case "vt":
		headers = GetHeaders(&VirusTotalAttributes{})
	}

	// create our csv file
	outputFile, err := os.Create(*out)
	if err != nil {
		panic(err)
	}
	writer := csv.NewWriter(outputFile)
	defer writer.Flush()

	log.Printf("Starting to write %d values to csv...", len(entries))

	// headers
	if err := writer.Write(headers); err != nil {
		panic(err)
	}

	// values
	entriesWritten := 0
	for _, entry := range entries {
		log.Printf("Getting info for %s", entry)
		info, err := getIpInfo(entry)
		if err != nil {
			log.Println(err)
			continue
		}

		if err := writer.Write(GetValues(info)); err != nil {
			panic(err)
		}

		entriesWritten += 1
	}

	log.Printf("Finished writing %d values to csv", entriesWritten)
}

func toJson(ipSlice []string, out *string) {
	values := make([]interface{}, len(ipSlice))
	idx := 0

	for _, ip := range ipSlice {
		log.Printf("Getting IP info for %s", ip)
		ipInfo, err := getIpInfo(ip)
		if err != nil {
			log.Print(err)
			continue
		}

		values[idx] = ipInfo
		idx++
	}

	content, err := json.MarshalIndent(values, "", "    ")
	if err != nil {
		log.Print(err)
	}

	log.Printf("Starting to write %d values to json...", len(values))
	os.WriteFile(*out, content, 0644)
}
