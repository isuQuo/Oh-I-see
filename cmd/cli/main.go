package main

import (
	"flag"
	"fmt"
	"log"
	"strings"

	"github.com/isuQuo/OhISee/cmd/cli/config"
	"github.com/isuQuo/OhISee/cmd/cli/export"
	"github.com/isuQuo/OhISee/cmd/cli/provider"
	"github.com/isuQuo/OhISee/cmd/cli/utils"
)

var method string

func main() {
	availableMethods := []string{"abuseipdb", "vt"}
	availableExports := []string{"csv", "json"}

	inputFile := flag.String("in", "", "input file. List of indicators separated by newlines")
	outputFile := flag.String("out", "", fmt.Sprintf("output file. Choices are %s", availableExports))
	checkMethod := flag.String("method", "", fmt.Sprintf("Choices are %s", availableMethods))
	flag.Parse()

	if !utils.CheckMethods(*checkMethod, availableMethods) {
		log.Fatalf("Choices are %s", availableMethods)
	}
	method = *checkMethod

	// Get the input file and generate a slice of IPs
	content := utils.ReadFile(*inputFile)
	indicators := utils.RemoveDuplicates(utils.GenerateContentSlice(content))

	configuration := config.LoadConfig()
	ipInfoProvider := provider.GetProvider(method, configuration)

	if strings.Contains(*outputFile, ".csv") {
		export.ToCsv(indicators, outputFile, ipInfoProvider)
	} else if strings.Contains(*outputFile, ".json") {
		export.ToJson(indicators, outputFile, ipInfoProvider)
	} else {
		log.Fatal("invalid export choice")
	}
}
