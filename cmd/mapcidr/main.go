package main

import (
	"bufio"
	"bytes"
	"math/big"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/projectdiscovery/fileutil"
	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/projectdiscovery/ipranger"
	"github.com/projectdiscovery/mapcidr"
)

// Options contains cli options
type Options struct {
	FileIps         string
	Slices          int
	HostCount       int
	Cidr            string
	FileCidr        string
	Silent          bool
	Version         bool
	Output          string
	Aggregate       bool
	Shuffle         bool
	ShufflePorts    string
	SkipBaseIP      bool
	SkipBroadcastIP bool
	AggregateApprox bool
	SortAscending   bool
	SortDescending  bool
	Count           bool

}

const banner = `
                   ____________  ___    
  __ _  ___ ____  / ___/  _/ _ \/ _ \   
 /  ' \/ _ '/ _ \/ /___/ // // / , _/   
/_/_/_/\_,_/ .__/\___/___/____/_/|_| v0.0.9
          /_/                                                     	 
`

// Version is the current version of mapcidr
const Version = `v0.0.9`

// showBanner is used to show the banner to the user
func showBanner() {
	gologger.Print().Msgf("%s\n", banner)
	gologger.Print().Msgf("\t\tprojectdiscovery.io\n\n")

	gologger.Print().Msgf("Use with caution. You are responsible for your actions\n")
	gologger.Print().Msgf("Developers assume no liability and are not responsible for any misuse or damage.\n")
}

// ParseOptions parses the command line options for application
func ParseOptions() *Options {
	options := &Options{}
	flagSet := goflags.NewFlagSet()
	flagSet.SetDescription(`mapCIDR is developed to ease load distribution for mass scanning operations, it can be used both as a library and as independent CLI tool.`)

	//input
	createGroup(flagSet, "input", "Input",
		flagSet.StringVar(&options.Cidr, "cidr", "", "CIDR to process"),
		flagSet.StringVarP(&options.FileCidr, "list", "l", "", "File containing list of CIDRs to process"),
		flagSet.StringVarP(&options.FileIps, "ip-list", "il", "", "File containing list of IPs to process"),
	)

	//Process
	createGroup(flagSet, "process", "Process",
		flagSet.IntVar(&options.Slices, "sbc", 0, "Slice CIDRs by given CIDR count"),
		flagSet.IntVar(&options.HostCount, "sbh", 0, "Slice CIDRs by given HOST count"),
		flagSet.BoolVarP(&options.AggregateApprox, "aggregate-approx", "agg-approx", false, "Aggregate input with sparse IPs/CIDRs in the minimum set of approximated subnets"),
		flagSet.BoolVarP(&options.Aggregate, "aggregate", "agg", false, "Aggregate IPs/CIDRs into the minimum subnet"),
		flagSet.BoolVarP(&options.Count, "count", "c", false, "Count number of hosts in given CIDR"),
		flagSet.BoolVarP(&options.SortAscending, "sort", "s", false, "Sort input IPs/CIDRs in ascending order"),
		flagSet.BoolVarP(&options.SortDescending, "sort-reverse", "sr", false, "Sort input IPs/CIDRs in descending order"),
		flagSet.BoolVarP(&options.Shuffle, "shuffle-ip", "si", false, "Shuffle input ip"),
		flagSet.StringVarP(&options.ShufflePorts, "shuffle-port", "sp", "", "Shuffle input ip:port"),
	)

	//output
	createGroup(flagSet, "output", "Output",
		flagSet.StringVarP(&options.Output, "output", "o", "", "File to write output to"),
		flagSet.BoolVar(&options.Silent, "silent", false, "Silent mode"),
		flagSet.BoolVar(&options.Version, "version", false, "Show version"),
		flagSet.BoolVar(&options.SkipBaseIP, "skip-base", false, "Skip base IPs (ending in .0) in output"),
		flagSet.BoolVar(&options.SkipBroadcastIP, "skip-broadcast", false, "Skip broadcast IPs (ending in .255) in output"),
	)

	_ = flagSet.Parse()

	// Read the inputs and configure the logging
	options.configureOutput()

	showBanner()

	if options.Version {
		gologger.Info().Msgf("Current Version: %s\n", Version)
		os.Exit(0)
	}

	// enable shuffling if ports are specified
	if len(options.ShufflePorts) > 0 {
		options.Shuffle = true
	}

	options.validateOptions()

	return options
}

func (options *Options) validateOptions() {
	if options.Cidr == "" && !fileutil.HasStdin() && options.FileCidr == "" && options.FileIps == "" {
		gologger.Fatal().Msgf("No input provided!\n")
	}

	if options.Slices > 0 && options.HostCount > 0 {
		gologger.Fatal().Msgf("sbc and sbh cant be used together!\n")
	}

	if options.Cidr != "" && options.FileCidr != "" {
		gologger.Fatal().Msgf("CIDR and List input cant be used together!\n")
	}

	if options.SortAscending && options.SortDescending {
		gologger.Fatal().Msgf("Can sort only in one direction!\n")
	}
}

// configureOutput configures the output on the screen
func (options *Options) configureOutput() {
	if options.Silent {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelSilent)
	}
}

var options *Options

func main() {
	options = ParseOptions()
	chanips := make(chan string)
	chancidr := make(chan string)
	outputchan := make(chan string)
	var wg sync.WaitGroup

	wg.Add(1)
	go process(&wg, chancidr, chanips, outputchan)
	wg.Add(1)
	go output(&wg, outputchan)

	if options.Cidr != "" {
		chancidr <- options.Cidr
	}

	if fileutil.HasStdin() {
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			chancidr <- scanner.Text()
		}
	}

	if options.FileCidr != "" {
		file, err := os.Open(options.FileCidr)
		if err != nil {
			gologger.Fatal().Msgf("%s\n", err)
		}
		defer file.Close() //nolint
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			chancidr <- scanner.Text()
		}
	}

	close(chancidr)

	// Start to process ips list
	if options.FileIps != "" {
		file, err := os.Open(options.FileIps)
		if err != nil {
			gologger.Fatal().Msgf("%s\n", err)
		}
		defer file.Close() //nolint
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			chanips <- scanner.Text()
		}
	}

	close(chanips)

	wg.Wait()
}

func process(wg *sync.WaitGroup, chancidr, chanips, outputchan chan string) {
	defer wg.Done()
	var (
		allCidrs []*net.IPNet
		pCidr    *net.IPNet
		ranger   *ipranger.IPRanger
		err      error
		hasSort  = options.SortAscending || options.SortDescending
	)

	ranger, _ = ipranger.New()

	for cidr := range chancidr {
		// if it's an ip turn it into a cidr
		if net.ParseIP(cidr) != nil {
			cidr += "/32"
		}

		// test if we have a cidr
		if _, pCidr, err = net.ParseCIDR(cidr); err != nil {
			gologger.Fatal().Msgf("%s\n", err)
		}

		// In case of coalesce/shuffle we need to know all the cidrs and aggregate them by calling the proper function
		if options.Aggregate || options.FileIps != "" || options.Shuffle || hasSort || options.AggregateApprox || options.Count {
			_ = ranger.AddIPNet(pCidr)
			allCidrs = append(allCidrs, pCidr)
		} else if options.Slices > 0 {
			subnets, err := mapcidr.SplitN(cidr, options.Slices)
			if err != nil {
				gologger.Fatal().Msgf("%s\n", err)
			}
			for _, subnet := range subnets {
				outputchan <- subnet.String()
			}
		} else if options.HostCount > 0 {
			subnets, err := mapcidr.SplitByNumber(cidr, options.HostCount)
			if err != nil {
				gologger.Fatal().Msgf("%s\n", err)
			}
			for _, subnet := range subnets {
				outputchan <- subnet.String()
			}
		} else {
			ips, err := mapcidr.IPAddressesAsStream(cidr)
			if err != nil {
				gologger.Fatal().Msgf("%s\n", err)
			}
			for ip := range ips {
				outputchan <- ip
			}
		}
	}

	// Shuffle perform the aggregation
	if options.Shuffle {
		var ports []int
		if options.ShufflePorts != "" {
			for _, p := range strings.Split(options.ShufflePorts, ",") {
				port, err := strconv.Atoi(p)
				if err != nil {
					gologger.Fatal().Msgf("%s\n", err)
				}
				ports = append(ports, port)
			}
		}
		cCidrsIPV4, _ := mapcidr.CoalesceCIDRs(allCidrs)
		if len(ports) > 0 {
			for ip := range mapcidr.ShuffleCidrsWithPortsAndSeed(cCidrsIPV4, ports, time.Now().Unix()) {
				outputchan <- ip.String()
			}
		} else {
			for ip := range mapcidr.ShuffleCidrsWithSeed(cCidrsIPV4, time.Now().Unix()) {
				outputchan <- ip.IP
			}
		}
	}

	// Aggregate all ips into the minimal subset possible
	if options.Aggregate {
		cCidrsIPV4, cCidrsIPV6 := mapcidr.CoalesceCIDRs(allCidrs)
		for _, cidrIPV4 := range cCidrsIPV4 {
			outputchan <- cidrIPV4.String()
		}
		for _, cidrIPV6 := range cCidrsIPV6 {
			outputchan <- cidrIPV6.String()
		}
	}

	if hasSort {
		if options.FileIps != "" {
			var ips []net.IP
			for ip := range chanips {
				ips = append(ips, net.ParseIP(ip))
			}
			if options.SortDescending {
				sort.Slice(ips, func(i, j int) bool {
					return bytes.Compare(ips[j], ips[i]) < 0
				})
			} else {
				sort.Slice(ips, func(i, j int) bool {
					return bytes.Compare(ips[i], ips[j]) < 0
				})
			}

			for _, ip := range ips {
				outputchan <- ip.String()
			}
		} else {
			if options.SortDescending {
				sort.Slice(allCidrs, func(i, j int) bool {
					return bytes.Compare(allCidrs[j].IP, allCidrs[i].IP) < 0
				})
			} else {
				sort.Slice(allCidrs, func(i, j int) bool {
					return bytes.Compare(allCidrs[i].IP, allCidrs[j].IP) < 0
				})
			}
			for _, cidr := range allCidrs {
				outputchan <- cidr.String()
			}
		}
	}

	if options.AggregateApprox {
		for _, cidr := range mapcidr.AggregateApproxIPV4s(allCidrs) {
			outputchan <- cidr.String()
		}
	}

	if options.Count {
		ipSum := big.NewInt(0)
		for _, cidr := range allCidrs {
			ipSum = ipSum.Add(ipSum, mapcidr.CountIPsInCIDR(cidr))
		}
		outputchan <- ipSum.String()
	}


	// Process all ips if any
	for ip := range chanips {
		if ranger.Contains(ip) {
			outputchan <- ip
		}
	}

	close(outputchan)
}

func output(wg *sync.WaitGroup, outputchan chan string) {
	defer wg.Done()

	var f *os.File
	if options.Output != "" {
		var err error
		f, err = os.Create(options.Output)
		if err != nil {
			gologger.Fatal().Msgf("Could not create output file '%s': %s\n", options.Output, err)
		}
		defer f.Close() //nolint
	}
	for o := range outputchan {
		if o == "" {
			continue
		}
		if options.SkipBaseIP && mapcidr.IsBaseIP(o) {
			continue
		}
		if options.SkipBroadcastIP && mapcidr.IsBroadcastIP(o) {
			continue
		}

		gologger.Silent().Msgf("%s\n", o)
		if f != nil {
			_, _ = f.WriteString(o + "\n")
		}
	}
}

func createGroup(flagSet *goflags.FlagSet, groupName, description string, flags ...*goflags.FlagData) {
	flagSet.SetGroup(groupName, description)
	for _, currentFlag := range flags {
		currentFlag.Group(groupName)
	}
}
