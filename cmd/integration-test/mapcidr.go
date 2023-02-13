package main

import (
	"fmt"
	"os"
	"strings"

	"golang.org/x/exp/slices"
)

type TestCase interface {
	// Execute executes a test case and returns any errors if occurred
	Execute() error
}

type mapCidrQuery struct {
	question       string
	args           string
	expectedOutput []string
}

type mapCidrQueryOutputFile struct {
	question       string
	args           string
	expectedOutput []string
	outputfile     string
}

var mapcidrTestcases = map[string]TestCase{
	// CIDR
	"CIDR Exapansion":                      &mapCidrQuery{question: "192.168.0.0/30", expectedOutput: []string{"192.168.0.0", "192.168.0.1", "192.168.0.2", "192.168.0.3"}},
	"Multiple CIDR Exapansion":             &mapCidrQuery{question: "192.168.0.0/30,10.50.0.0/30", expectedOutput: []string{"192.168.0.0", "192.168.0.1", "192.168.0.2", "192.168.0.3", "10.50.0.0", "10.50.0.1", "10.50.0.2", "10.50.0.3"}},
	"Slice CIDRs by given CIDR count":      &mapCidrQuery{question: "173.0.84.0/24", expectedOutput: []string{"173.0.84.0/27", "173.0.84.32/27", "173.0.84.64/27", "173.0.84.96/27", "173.0.84.128/27", "173.0.84.160/27", "173.0.84.208/28", "173.0.84.192/28", "173.0.84.240/28", "173.0.84.224/28"}, args: "-sbc 10"},
	"Slice CIDRs by given host count":      &mapCidrQuery{question: "173.0.0.0/16", expectedOutput: []string{"173.0.0.0/18", "173.0.64.0/18", "173.0.128.0/18", "173.0.192.0/18"}, args: "-sbh 20000"},
	"CIDR Arggregation":                    &mapCidrQuery{question: "173.0.0.0/18,173.0.64.0/18,173.0.128.0/18,173.0.192.0/18", expectedOutput: []string{"173.0.0.0/16"}, args: "-a"},
	"CIDR Arggregation(file)":              &mapCidrQuery{question: "", expectedOutput: []string{"173.0.0.0/16"}, args: "-cl ./tests/cidrs_a.txt -a"},
	"CIDR Appox Arggregation(file)":        &mapCidrQuery{question: "", expectedOutput: []string{"1.1.1.0/27"}, args: "-cl ./tests/ips_aa.txt -aa"},
	"CIDR IP Count":                        &mapCidrQuery{question: "173.0.84.0/24,10.0.0.0/24", expectedOutput: []string{"512"}, args: "-c"},
	"Match IP's(args) from CIDR":           &mapCidrQuery{question: "192.168.1.0/24", expectedOutput: []string{"192.168.1.253", "192.168.1.252"}, args: "-mi 192.168.1.253,192.168.1.252"},
	"Match IP's(file) from CIDR":           &mapCidrQuery{question: "192.168.1.0/24", expectedOutput: []string{"192.168.1.253", "192.168.1.252"}, args: "-mi ./tests/ip_list_to_match.txt"},
	"Filter IP's(args) from CIDR":          &mapCidrQuery{question: "192.168.1.0/30", expectedOutput: []string{"192.168.1.0", "192.168.1.2"}, args: "-fi 192.168.1.1,192.168.1.3"},
	"Filter IP's(file) from CIDR":          &mapCidrQuery{question: "192.168.1.0/30", expectedOutput: []string{"192.168.1.0", "192.168.1.2"}, args: "-fi ./tests/ip_list_to_filter.txt"},
	"Convert IPs to IPv6":                  &mapCidrQuery{question: "192.168.0.0/30", expectedOutput: []string{"00:00:00:00:00:ffff:c0a8:0000", "00:00:00:00:00:ffff:c0a8:0001", "00:00:00:00:00:ffff:c0a8:0002", "00:00:00:00:00:ffff:c0a8:0003"}, args: "-t6"},
	"CIDR Skip Base":                       &mapCidrQuery{question: "192.168.1.0/30", expectedOutput: []string{"192.168.1.1", "192.168.1.2", "192.168.1.3"}, args: "-skip-base"},
	"CIDR Skip Broadcast":                  &mapCidrQuery{question: "192.168.0.255/30", expectedOutput: []string{"192.168.0.252", "192.168.0.253", "192.168.0.254"}, args: "-skip-broadcast"},
	"CIDR Sort (ascending order)":          &mapCidrQuery{question: "192.168.0.0/30", expectedOutput: []string{"192.168.0.0", "192.168.0.1", "192.168.0.2", "192.168.0.3"}, args: "-s"},
	"CIDR Reverse Sort (descending order)": &mapCidrQuery{question: "10.40.1.0/30", expectedOutput: []string{"10.40.1.3", "10.40.1.2", "10.40.1.1", "10.40.1.0"}, args: "-sr"},
	"CIDR Shuffle IPs":                     &mapCidrQuery{question: "192.168.0.0/30", expectedOutput: []string{"192.168.0.3", "192.168.0.0", "192.168.0.1", "192.168.0.2"}, args: "-si"},
	"CIDR Shuffle Port IPs":                &mapCidrQuery{question: "192.168.0.0/30", expectedOutput: []string{"192.168.0.3:8080", "192.168.0.0:8080", "192.168.0.1:8080", "192.168.0.2:8080"}, args: "-sp 8080"},
	"CIDR Shuffle Multiple Port IPs":       &mapCidrQuery{question: "192.168.0.0/30", expectedOutput: []string{"192.168.0.3:8080", "192.168.0.0:8080", "192.168.0.1:8080", "192.168.0.2:8080", "192.168.0.3:9090", "192.168.0.0:9090", "192.168.0.1:9090", "192.168.0.2:9090"}, args: "-sp 8080,9090"},

	//IP range
	"IPRange Exapansion":                      &mapCidrQuery{question: "192.168.0.0-192.168.0.3", expectedOutput: []string{"192.168.0.0", "192.168.0.1", "192.168.0.2", "192.168.0.3"}},
	"Multiple IPRange Exapansion":             &mapCidrQuery{question: "192.168.0.0-192.168.0.3,192.168.0.4-192.168.0.10", expectedOutput: []string{"192.168.0.0", "192.168.0.1", "192.168.0.2", "192.168.0.3", "192.168.0.4", "192.168.0.5", "192.168.0.6", "192.168.0.7", "192.168.0.8", "192.168.0.9", "192.168.0.10"}},
	"IPRange Aggregation":                     &mapCidrQuery{question: "192.168.0.0-192.168.0.3", expectedOutput: []string{"192.168.0.0/30"}, args: "-a"},
	"Multiple IPRange Aggregation":            &mapCidrQuery{question: "192.168.0.0-192.168.0.128,192.168.0.129-192.168.0.255", expectedOutput: []string{"192.168.0.0/24"}, args: "-a"},
	"IPRange IP count":                        &mapCidrQuery{question: "192.168.0.0-192.168.0.255", expectedOutput: []string{"256"}, args: "-c"},
	"Match IP's(args) from IPRange":           &mapCidrQuery{question: "192.168.0.0-192.168.0.3", expectedOutput: []string{"192.168.0.1", "192.168.0.3"}, args: "-mi 192.168.0.1,192.168.0.3"},
	"Filter IP's(file) from IPRange":          &mapCidrQuery{question: "192.168.0.0-192.168.0.3", expectedOutput: []string{"192.168.0.0", "192.168.0.2"}, args: "-fi 192.168.0.1,192.168.0.3"},
	"Convert IPs to IPv6 from IPRange":        &mapCidrQuery{question: "192.168.0.0-192.168.0.3", expectedOutput: []string{"00:00:00:00:00:ffff:c0a8:0000", "00:00:00:00:00:ffff:c0a8:0001", "00:00:00:00:00:ffff:c0a8:0002", "00:00:00:00:00:ffff:c0a8:0003"}, args: "-t6"},
	"Slice IPRange by given CIDR count":       &mapCidrQuery{question: "173.0.84.0-173.0.84.255", expectedOutput: []string{"173.0.84.0/27", "173.0.84.32/27", "173.0.84.64/27", "173.0.84.96/27", "173.0.84.128/27", "173.0.84.160/27", "173.0.84.208/28", "173.0.84.192/28", "173.0.84.240/28", "173.0.84.224/28"}, args: "-sbc 10"},
	"Slice IPRange by given host count":       &mapCidrQuery{question: "173.0.0.0-173.0.255.255", expectedOutput: []string{"173.0.0.0/18", "173.0.64.0/18", "173.0.128.0/18", "173.0.192.0/18"}, args: "-sbh 20000"},
	"IPRange Skip Base":                       &mapCidrQuery{question: "192.168.0.0-192.168.0.3", expectedOutput: []string{"192.168.0.1", "192.168.0.2", "192.168.0.3"}, args: "-skip-base"},
	"IPRange Skip Broadcast":                  &mapCidrQuery{question: "192.168.0.252-192.168.0.255", expectedOutput: []string{"192.168.0.252", "192.168.0.253", "192.168.0.254"}, args: "-skip-broadcast"},
	"IPRange Sort (ascending order)":          &mapCidrQuery{question: "192.168.0.0-192.168.0.3", expectedOutput: []string{"192.168.0.0", "192.168.0.1", "192.168.0.2", "192.168.0.3"}, args: "-s"},
	"IPRange Reverse Sort (descending order)": &mapCidrQuery{question: "192.168.1.0-192.168.1.3", expectedOutput: []string{"192.168.1.3", "192.168.1.2", "192.168.1.1", "192.168.1.0"}, args: "-sr"},
	"IPRange Shuffle IPs":                     &mapCidrQuery{question: "192.168.0.0-192.168.0.3", expectedOutput: []string{"192.168.0.3", "192.168.0.0", "192.168.0.1", "192.168.0.2"}, args: "-si"},
	"IPRange Shuffle Port IPs":                &mapCidrQuery{question: "173.0.0.0-173.0.0.3", expectedOutput: []string{"173.0.0.3:8080", "173.0.0.0:8080", "173.0.0.1:8080", "173.0.0.2:8080"}, args: "-sp 8080"},
	"IPRange Shuffle Multiple Port IPs":       &mapCidrQuery{question: "192.168.0.0-192.168.0.3", expectedOutput: []string{"192.168.0.3:8080", "192.168.0.0:8080", "192.168.0.1:8080", "192.168.0.2:8080", "192.168.0.3:9090", "192.168.0.0:9090", "192.168.0.1:9090", "192.168.0.2:9090"}, args: "-sp 8080,9090"},

	// sort IPs from file
	"IPs Sort (ascending order)":  &mapCidrQuery{question: "", expectedOutput: []string{"1.1.1.1", "2.2.2.2", "2.4.3.2", "2.4.4.4", "8.8.8.8", "9.9.9.9", "255.255.255.255"}, args: "-cl ./tests/ips_sort.txt -s"},
	"IPs Sort (descending order)": &mapCidrQuery{question: "", expectedOutput: []string{"255.255.255.255", "9.9.9.9", "8.8.8.8", "2.4.4.4", "2.4.3.2", "2.2.2.2", "1.1.1.1"}, args: "-cl ./tests/ips_sort.txt -s"},

	// combination of IPRange and CIDRs
	"IPRange & CIDR Aggregation":         &mapCidrQuery{question: "166.8.0.0/16,166.11.0.0/16,166.9.0.0-166.10.255.255", expectedOutput: []string{"166.8.0.0/14"}, args: "-a"},
	"IPRange & CIDR Aggregation(file)":   &mapCidrQuery{question: "", expectedOutput: []string{"166.8.0.0/14"}, args: "-cl ./tests/ip_cidr.txt -a"},
	"IPRange & CIDR Expansion":           &mapCidrQuery{question: "192.168.0.0/30,192.168.0.4-192.168.0.10", expectedOutput: []string{"192.168.0.0", "192.168.0.1", "192.168.0.2", "192.168.0.3", "192.168.0.4", "192.168.0.5", "192.168.0.6", "192.168.0.7", "192.168.0.8", "192.168.0.9", "192.168.0.10"}},
	"IPRange & CIDR Count":               &mapCidrQuery{question: "166.8.0.0/16,166.11.0.0/16,166.9.0.0-166.10.255.255", expectedOutput: []string{"262144"}, args: "-c"},
	"IPRange & CIDR convert IPs to IPv6": &mapCidrQuery{question: "192.168.0.0-192.168.0.3", expectedOutput: []string{"00:00:00:00:00:ffff:c0a8:0000", "00:00:00:00:00:ffff:c0a8:0001", "00:00:00:00:00:ffff:c0a8:0002", "00:00:00:00:00:ffff:c0a8:0003"}, args: "-t6"},

	// output
	"OutputFile case": &mapCidrQueryOutputFile{question: "192.168.0.0/30", expectedOutput: []string{"192.168.0.0", "192.168.0.1", "192.168.0.2", "192.168.0.3"}, args: "-o /tmp/output.txt", outputfile: "/tmp/output.txt"},

	// use as library
	"use as library - ip test":                 &ipIntegrationTest{Input: "192.168.1.0/32", Expected: []string{"192.168.1.0"}},
	"use as library - cidr as IP net test":     &cidrAsIPNETIntegrationTest{Input: "192.168.1.0/32,192.168.1.0/28", Expected: []string{"192.168.1.0/32", "192.168.1.0/28"}},
	"use as library - cidr from IP range test": &getCIDRFromIPRANGEIntegrationTest{Input: "192.168.1.0,192.168.1.1", Expected: []string{"192.168.1.0/31"}},
}

func (h *mapCidrQuery) Execute() error {
	result, err := RunMapCidrAndGetResults(h.question, debug, h.args)
	if err != nil {
		return err
	}
	return compareResult(h.expectedOutput, result)
}

func (h *mapCidrQueryOutputFile) Execute() error {
	_, err := RunMapCidrAndGetResults(h.question, debug, h.args)
	if err != nil {
		return err
	}
	// read output file and compare result
	fileContent, err := os.ReadFile(h.outputfile)
	if err != nil {
		return err
	}
	result := []string{}
	items := strings.Split(string(fileContent), "\n")
	for _, i := range items {
		if i != "" {
			result = append(result, i)
		}
	}
	return compareResult(h.expectedOutput, result)
}

func errIncorrectResultsCount(results []string) error {
	return fmt.Errorf("incorrect number of results %s", strings.Join(results, "\n\t"))
}

func errIncorrectResult(expected, got []string) error {
	return fmt.Errorf("incorrect result: expected \"%s\" got \"%s\"", expected, got)
}

func compareResult(expected, result []string) error {
	// check if incorrent number of result
	if len(result) != len(expected) {
		return errIncorrectResultsCount(result)
	}
	for _, v := range result {
		if !slices.Contains(expected, v) {
			return errIncorrectResult(expected, result)
		}
	}
	return nil
}
