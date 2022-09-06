package main

import (
	"reflect"
	"sync"
	"testing"
)

func TestProcess(t *testing.T) {
	tests := []struct {
		name           string
		chancidr       chan string
		outputchan     chan string
		options        Options
		expectedOutput []string
	}{
		{
			name:       "CIDRExpansionIPv4",
			chancidr:   make(chan string),
			outputchan: make(chan string),
			options: Options{
				FileCidr: []string{"10.40.0.0/30"},
			},
			expectedOutput: []string{"10.40.0.0", "10.40.0.1", "10.40.0.2", "10.40.0.3"},
		},
		{
			name:       "CIDRExpansionIPv6",
			chancidr:   make(chan string),
			outputchan: make(chan string),
			options: Options{
				FileCidr: []string{"2c0f:fec9::/126"},
			},
			expectedOutput: []string{"2c0f:fec9::", "2c0f:fec9::1", "2c0f:fec9::2", "2c0f:fec9::3"},
		},
		{
			name:       "CIDRAggregationIPv4",
			chancidr:   make(chan string),
			outputchan: make(chan string),
			options: Options{

				FileCidr:  []string{"10.40.0.0/30", "10.40.0.4/30", "10.40.0.8/30", "10.40.0.12/30"},
				Aggregate: true,
			},
			expectedOutput: []string{"10.40.0.0/28"},
		},
		{
			name:       "CIDRSliceByCountIPv4",
			chancidr:   make(chan string),
			outputchan: make(chan string),
			options: Options{

				FileCidr: []string{"10.40.0.0/24"},
				Slices:   2,
			},
			expectedOutput: []string{"10.40.0.0/25", "10.40.0.128/25"},
		},
		{
			name:       "CIDRSliceByHostIPv4",
			chancidr:   make(chan string),
			outputchan: make(chan string),
			options: Options{

				FileCidr:  []string{"10.40.0.0/24"},
				HostCount: 128,
			},
			expectedOutput: []string{"10.40.0.0/25", "10.40.0.128/25"},
		},
		{
			name:       "IPRangeExpansionIPv4",
			chancidr:   make(chan string),
			outputchan: make(chan string),
			options: Options{

				FileCidr:     []string{"10.40.0.0", "10.40.0.5"},
				IPRangeInput: true,
			},
			expectedOutput: []string{"10.40.0.0", "10.40.0.1", "10.40.0.2", "10.40.0.3", "10.40.0.4", "10.40.0.5"},
		},
		{
			name:       "IPRangeExpansionIPv6",
			chancidr:   make(chan string),
			outputchan: make(chan string),
			options: Options{

				FileCidr:     []string{"2c0f:fec9::", "2c0f:fec9::3"},
				IPRangeInput: true,
			},
			expectedOutput: []string{"2c0f:fec9::", "2c0f:fec9::1", "2c0f:fec9::2", "2c0f:fec9::3"},
		},
		{
			name:       "IPRangeAggregationIPv4",
			chancidr:   make(chan string),
			outputchan: make(chan string),
			options: Options{

				FileCidr:     []string{"10.40.0.1", "10.40.0.255"},
				Aggregate:    true,
				IPRangeInput: true,
			},
			expectedOutput: []string{"10.40.0.64/26", "10.40.0.32/27", "10.40.0.16/28", "10.40.0.8/29", "10.40.0.4/30", "10.40.0.2/31", "10.40.0.1/32", "10.40.0.128/25"},
		},
		{
			name:       "IPRangeAggregationIPv6",
			chancidr:   make(chan string),
			outputchan: make(chan string),
			options: Options{

				FileCidr:     []string{"2c0f:fec9::", "2c0f:fed7:ffff:ffff:ffff:ffff:ffff:ffff"},
				Aggregate:    true,
				IPRangeInput: true,
			},
			expectedOutput: []string{"2c0f:fecc::/30", "2c0f:feca::/31", "2c0f:fec9::/32", "2c0f:fed0::/29"},
		},
		{
			name:       "IPRangeliceByCountIPv4",
			chancidr:   make(chan string),
			outputchan: make(chan string),
			options: Options{

				FileCidr:     []string{"10.40.0.0", "10.40.0.255"},
				Slices:       2,
				IPRangeInput: true,
			},
			expectedOutput: []string{"10.40.0.0/25", "10.40.0.128/25"},
		},
		{
			name:       "IPRangeSliceByHostIPv4",
			chancidr:   make(chan string),
			outputchan: make(chan string),
			options: Options{

				FileCidr:     []string{"10.40.0.0", "10.40.0.255"},
				HostCount:    128,
				IPRangeInput: true,
			},
			expectedOutput: []string{"10.40.0.0/25", "10.40.0.128/25"},
		},
	}
	var wg sync.WaitGroup

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wg.Add(2)
			options = &tt.options

			go process(&wg, tt.chancidr, tt.outputchan)

			var outputlist []string
			// get output list
			go func() {
				for output := range tt.outputchan {
					outputlist = append(outputlist, output)
				}
				wg.Done()
			}()

			for _, item := range tt.options.FileCidr {
				tt.chancidr <- item
			}
			close(tt.chancidr)
			wg.Wait()

			// compare output
			if !reflect.DeepEqual(outputlist, tt.expectedOutput) {
				t.Errorf("RangeToCIDRs() = %v, want %v", outputlist, tt.expectedOutput)
			}
		})

	}
}
