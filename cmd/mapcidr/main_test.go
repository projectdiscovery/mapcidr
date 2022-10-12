package main

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
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

				FileCidr: []string{"10.40.0.0-10.40.0.5"},
			},
			expectedOutput: []string{"10.40.0.0", "10.40.0.1", "10.40.0.2", "10.40.0.3", "10.40.0.4", "10.40.0.5"},
		},
		{
			name:       "IPRangeExpansionIPv6",
			chancidr:   make(chan string),
			outputchan: make(chan string),
			options: Options{

				FileCidr: []string{"2c0f:fec9::-2c0f:fec9::3"},
			},
			expectedOutput: []string{"2c0f:fec9::", "2c0f:fec9::1", "2c0f:fec9::2", "2c0f:fec9::3"},
		},
		{
			name:       "IPRangeAggregationIPv4",
			chancidr:   make(chan string),
			outputchan: make(chan string),
			options: Options{

				FileCidr:  []string{"10.40.0.1-10.40.0.255"},
				Aggregate: true,
			},
			expectedOutput: []string{"10.40.0.64/26", "10.40.0.32/27", "10.40.0.16/28", "10.40.0.8/29", "10.40.0.4/30", "10.40.0.2/31", "10.40.0.1/32", "10.40.0.128/25"},
		},
		{
			name:       "IPRangeAggregationIPv6",
			chancidr:   make(chan string),
			outputchan: make(chan string),
			options: Options{

				FileCidr:  []string{"2c0f:fec9::-2c0f:fed7:ffff:ffff:ffff:ffff:ffff:ffff"},
				Aggregate: true,
			},
			expectedOutput: []string{"2c0f:fecc::/30", "2c0f:feca::/31", "2c0f:fec9::/32", "2c0f:fed0::/29"},
		},
		{
			name:       "IPRangeliceByCountIPv4",
			chancidr:   make(chan string),
			outputchan: make(chan string),
			options: Options{

				FileCidr: []string{"10.40.0.0-10.40.0.255"},
				Slices:   2,
			},
			expectedOutput: []string{"10.40.0.0/25", "10.40.0.128/25"},
		},
		{
			name:       "IPRangeSliceByHostIPv4",
			chancidr:   make(chan string),
			outputchan: make(chan string),
			options: Options{

				FileCidr:  []string{"10.40.0.0-10.40.0.255"},
				HostCount: 128,
			},
			expectedOutput: []string{"10.40.0.0/25", "10.40.0.128/25"},
		}, {
			name:       "CombinationOneIPRangeAggregate",
			chancidr:   make(chan string),
			outputchan: make(chan string),
			options: Options{
				FileCidr:  []string{"166.8.0.0/16", "166.11.0.0/16", "166.9.0.0-166.10.255.255"},
				Aggregate: true,
			},
			expectedOutput: []string{"166.8.0.0/14"},
		}, {
			name:       "CombinationMultipleIPRangeAggregate",
			chancidr:   make(chan string),
			outputchan: make(chan string),
			options: Options{
				FileCidr:  []string{"173.0.0.0/18", "173.0.64.0-173.0.127.255", "173.0.128.0/18", "173.0.192.0-173.0.255.255"},
				Aggregate: true,
			},
			expectedOutput: []string{"173.0.0.0/16"},
		},
		{
			name:       "CombinationOneIPRangeCount",
			chancidr:   make(chan string),
			outputchan: make(chan string),
			options: Options{
				FileCidr: []string{"166.8.0.0/16", "166.11.0.0/16", "166.9.0.0-166.10.255.255"},
				Count:    true,
			},
			expectedOutput: []string{"262144"},
		}, {
			name:       "MultipleIPRangeAggregate",
			chancidr:   make(chan string),
			outputchan: make(chan string),
			options: Options{
				FileCidr:  []string{"166.8.0.0-166.8.0.5", "166.8.0.5-166.8.0.255"},
				Aggregate: true,
			},
			expectedOutput: []string{"166.8.0.0/24"},
		}, {
			name:       "IPsSortAscending",
			chancidr:   make(chan string),
			outputchan: make(chan string),
			options: Options{
				FileCidr:      []string{"1.1.1.1", "8.8.8.8", "255.255.255.255", "2.2.2.2", "2.4.4.4", "2.4.3.2", "9.9.9.9"},
				SortAscending: true,
			},
			expectedOutput: []string{"1.1.1.1", "2.2.2.2", "2.4.3.2", "2.4.4.4", "8.8.8.8", "9.9.9.9", "255.255.255.255"},
		}, {
			name:       "IPsSortDescending",
			chancidr:   make(chan string),
			outputchan: make(chan string),
			options: Options{
				FileCidr:       []string{"1.1.1.1", "255.255.255.255", "2.4.3.2", "2.2.2.2", "8.8.8.8", "2.4.4.4", "9.9.9.9"},
				SortDescending: true,
			},
			expectedOutput: []string{"255.255.255.255", "9.9.9.9", "8.8.8.8", "2.4.4.4", "2.4.3.2", "2.2.2.2", "1.1.1.1"},
		}, {
			name:       "CIDRsIPSortAscending",
			chancidr:   make(chan string),
			outputchan: make(chan string),
			options: Options{
				FileCidr:      []string{"10.40.0.0/30"},
				SortAscending: true,
			},
			expectedOutput: []string{"10.40.0.0", "10.40.0.1", "10.40.0.2", "10.40.0.3"},
		}, {
			name:       "CIDRsIPSortDescending",
			chancidr:   make(chan string),
			outputchan: make(chan string),
			options: Options{
				FileCidr:       []string{"10.40.1.0/30"},
				SortDescending: true,
			},
			expectedOutput: []string{"10.40.1.3", "10.40.1.2", "10.40.1.1", "10.40.1.0"},
		}, {
			name:       "IPRangeIPSortAscending",
			chancidr:   make(chan string),
			outputchan: make(chan string),
			options: Options{
				FileCidr:      []string{"192.168.0.0-192.168.0.3"},
				SortAscending: true,
			},
			expectedOutput: []string{"192.168.0.0", "192.168.0.1", "192.168.0.2", "192.168.0.3"},
		}, {
			name:       "IPRangeIIPSortDescending",
			chancidr:   make(chan string),
			outputchan: make(chan string),
			options: Options{
				FileCidr:       []string{"192.168.1.0-192.168.1.3"},
				SortDescending: true,
			},
			expectedOutput: []string{"192.168.1.3", "192.168.1.2", "192.168.1.1", "192.168.1.0"},
		},
	}
	var wg sync.WaitGroup

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			options = &tt.options

			wg.Add(1)
			go process(&wg, tt.chancidr, tt.outputchan)

			var outputlist []string
			// get output list
			wg.Add(1)
			go func() {
				defer wg.Done()
				for output := range tt.outputchan {
					outputlist = append(outputlist, output)
				}
			}()

			for _, item := range tt.options.FileCidr {
				tt.chancidr <- item
			}
			close(tt.chancidr)
			wg.Wait()

			// compare output
			require.Equal(t, tt.expectedOutput, outputlist)
		})

	}
}
