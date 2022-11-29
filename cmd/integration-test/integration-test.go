package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/logrusorgru/aurora"
)

var (
	debug      = os.Getenv("DEBUG") == "true"
	customTest = os.Getenv("TEST")
	errored    = false
	success    = aurora.Green("[✓]").String()
	failed     = aurora.Red("[✘]").String()
)

func main() {
	for name, testCase := range mapcidrTestcases {
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
