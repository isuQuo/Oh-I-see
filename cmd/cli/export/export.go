package export

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/isuQuo/OhISee/cmd/cli/provider"
	"github.com/isuQuo/OhISee/cmd/cli/utils"
)

func ToCsv(indicators []string, outputFile *string, provider provider.Provider) {
	file, err := os.Create(*outputFile)
	if err != nil {
		log.Fatal("Cannot create file", err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	var totalWrites int
	var headers []string
	fmt.Println("Writing number of rows:", len(indicators))
	for _, indicator := range indicators {
		fmt.Println("Checking indicator:", indicator)

		ioc := utils.IsAny(indicator, provider)

		if headers == nil {
			headers = provider.GetHeaders()
			err = writer.Write(headers)
			if err != nil {
				log.Fatal("Cannot write headers to file", err)
			}
		}

		row := provider.GetValues(ioc)

		err = writer.Write(row)
		if err != nil {
			log.Fatal("Cannot write to file", err)
		}

		totalWrites++
	}

	fmt.Println("Total rows written:", totalWrites)
}

func ToJson(indicators []string, outputFile *string, provider provider.Provider) {
	// Create a slice to store the results
	results := make([]map[string]interface{}, 0)

	var headers []string
	var totalWrites int
	fmt.Println("Writing number of objects:", len(indicators))
	for _, indicator := range indicators {
		fmt.Println("Checking indicator:", indicator)

		ioc := utils.IsAny(indicator, provider)

		if headers == nil {
			headers = provider.GetHeaders()
		}

		row := provider.GetValues(ioc)

		// Create a map to store the key-value pairs for each indicator
		result := make(map[string]interface{})
		for i, header := range headers {
			result[header] = row[i]
		}

		// Append the result map to the results slice
		results = append(results, result)

		totalWrites++
	}

	// Convert the slice to JSON
	jsonData, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		log.Fatalf("Error converting to JSON: %v", err)
	}

	// Write the JSON data to the output file
	err = ioutil.WriteFile(*outputFile, jsonData, 0644)
	if err != nil {
		log.Fatalf("Error writing JSON to file: %v", err)
	}

	fmt.Println("Total objects written:", totalWrites)
}
