package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/logrusorgru/aurora"
)

type TestCase interface {
	Execute() error
}

var (
	customTest = os.Getenv("TEST")
	success    = aurora.Green("[✓]").String()
	failed     = aurora.Red("[✘]").String()
	errored    = false
)
var specs = map[string]TestCase{
	"ip test":                 &ipIntegrationTest{Input: "192.168.1.0/32", Expected: []string{"192.168.1.0"}},
	"cidr as IP net test":     &cidrAsIPNETIntegrationTest{Input: "192.168.1.0/32,192.168.1.0/28", Expected: []string{"192.168.1.0/32", "192.168.1.0/28"}},
	"cidr from IP range test": &getCIDRFromIPRANGEIntegrationTest{Input: "192.168.1.0,192.168.1.1", Expected: []string{"192.168.1.0/31"}},
}

func main() {
	for name, testCase := range specs {
		if customTest != "" && !strings.Contains(name, customTest) {
			continue // only run tests user asked
		}
		fmt.Printf("Running test cases for \"%s\"\n", aurora.Cyan(name))
		err := testCase.Execute()
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s Test \"%s\" failed: %s\n", failed, name, err)
			errored = true
		} else {
			fmt.Printf("%s Test \"%s\" passed!\n", success, name)
		}
	}
	if errored {
		os.Exit(1)
	}
}
