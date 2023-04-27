package utils

import (
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"regexp"
	"strings"

	"github.com/isuQuo/OhISee/cmd/cli/provider"
)

func CheckMethods(method string, availableMethods []string) bool {
	set := make(map[string]struct{}, len(availableMethods))
	for _, s := range availableMethods {
		set[s] = struct{}{}
	}

	_, ok := set[method]
	return ok
}

func ReadFile(fileName string) []byte {
	content, err := os.ReadFile(fileName)
	if err != nil {
		log.Fatal(err)
	}
	return content
}

func GenerateContentSlice(content []byte) []string {
	contentSlice := []string{}

	contentSlice = append(contentSlice, strings.Split(string(content), "\n")...)

	return contentSlice
}

func RemoveDuplicates(elements []string) []string {
	set := make(map[string]struct{})
	for _, s := range elements {
		set[s] = struct{}{}
	}

	var result []string
	for k := range set {
		result = append(result, k)
	}

	return result
}

func isURL(str string) bool {
	_, err := url.ParseRequestURI(str)
	if err != nil {
		return false
	}
	u, err := url.Parse(str)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return false
	}

	return true
}

func isIPAddress(str string) bool {
	ip := net.ParseIP(str)
	return ip != nil
}

func isHash(str string) bool {
	hashRegex := regexp.MustCompile(`^([a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})$`)
	return hashRegex.MatchString(str)
}

// Check if indicator is a URL, IP, or hash
func IsAny(indicator string, provider provider.Provider) interface{} {
	if isURL(indicator) {
		indicator, err := provider.CheckURL(indicator)
		if err != nil {
			log.Printf("Error fetching info for URL %s: %v", indicator, err)
			return nil
		}
		return indicator

	} else if isIPAddress(indicator) {
		indicator, err := provider.CheckIP(indicator)
		if err != nil {
			log.Printf("Error fetching info for IP %s: %v", indicator, err)
			return nil
		}
		return indicator

	} else if isHash(indicator) {
		indicator, err := provider.CheckHash(indicator)
		if err != nil {
			log.Printf("Error fetching info for hash %s: %v", indicator, err)
			return nil
		}
		return indicator

	} else {
		fmt.Printf("Indicator %s is not a URL, IP, or hash\n", indicator)
		return nil
	}
}
