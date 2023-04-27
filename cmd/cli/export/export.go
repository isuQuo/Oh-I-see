package export

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
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

	// Write headers
	headers := provider.GetHeaders()
	err = writer.Write(headers)
	if err != nil {
		log.Fatal("Cannot write headers to file", err)
	}

	var totalWrites int
	fmt.Println("Writing number of rows:", len(indicators))
	for _, indicator := range indicators {
		fmt.Println("Checking indicator:", indicator)

		ioc := utils.IsAny(indicator, provider)
		row := provider.GetValues(ioc)

		err = writer.Write(row)
		if err != nil {
			log.Fatal("Cannot write to file", err)
		}

		totalWrites++
	}

	fmt.Println("Total rows written:", totalWrites)
}

func ToJson(ipSlice []string, outputFile *string, provider provider.Provider) {
	file, err := os.Create(*outputFile)
	if err != nil {
		log.Fatal("Cannot create file", err)
	}
	defer file.Close()

	enc := json.NewEncoder(file)
	ipInfoSlice := []interface{}{}

	for _, ip := range ipSlice {
		ipInfo, err := provider.CheckIP(ip)
		if err != nil {
			log.Printf("Error fetching info for IP %s: %v", ip, err)
			continue
		}

		ipInfoSlice = append(ipInfoSlice, ipInfo)
	}

	err = enc.Encode(ipInfoSlice)
	if err != nil {
		log.Fatal("Cannot write to file", err)
	}
}
