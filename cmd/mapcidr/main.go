package main

import (
	"bufio"
	"bytes"
	"errors"
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
	"github.com/projectdiscovery/sliceutil"
)

// Options contains cli options
type Options struct {
	Slices                int
	HostCount             int
	FileCidr              goflags.StringSlice
	Silent                bool
	Verbose               bool
	Version               bool
	Output                string
	Aggregate             bool
	Shuffle               bool
	ShufflePorts          string
	SkipBaseIP            bool
	SkipBroadcastIP       bool
	AggregateApprox       bool
	SortAscending         bool
	SortDescending        bool
	Count                 bool
	FilterIP4             bool
	FilterIP6             bool
	ToIP4                 bool
	ToIP6                 bool
	MatchIP               goflags.StringSlice
	FilterIP              goflags.StringSlice
	IPFormats             goflags.StringSlice
	ZeroPadNumberOfZeroes int
	ZeroPadPermute        bool
}

const banner = `
                   ____________  ___    
  __ _  ___ ____  / ___/  _/ _ \/ _ \   
 /  ' \/ _ '/ _ \/ /___/ // // / , _/   
/_/_/_/\_,_/ .__/\___/___/____/_/|_| v1.0.1
          /_/                                                     	 
`

// Version is the current version of mapcidr
const Version = `v1.0.1`

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

	// Input
	flagSet.CreateGroup("input", "Input",
		flagSet.StringSliceVarP(&options.FileCidr, "cidr", "cl", nil, "CIDR/IP/File containing list of CIDR/IP to process", goflags.FileNormalizedStringSliceOptions),
	)

	// Process
	flagSet.CreateGroup("process", "Process",
		flagSet.IntVar(&options.Slices, "sbc", 0, "Slice CIDRs by given CIDR count"),
		flagSet.IntVar(&options.HostCount, "sbh", 0, "Slice CIDRs by given HOST count"),
		flagSet.BoolVarP(&options.Aggregate, "aggregate", "a", false, "Aggregate IPs/CIDRs into minimum subnet"),
		flagSet.BoolVarP(&options.AggregateApprox, "aggregate-approx", "aa", false, "Aggregate sparse IPs/CIDRs into minimum approximated subnet"),
		flagSet.BoolVarP(&options.Count, "count", "c", false, "Count number of IPs in given CIDR"),
		flagSet.BoolVarP(&options.ToIP4, "to-ipv4", "t4", false, "Convert IPs to IPv4 format"),
		flagSet.BoolVarP(&options.ToIP6, "to-ipv6", "t6", false, "Convert IPs to IPv6 format"),
		flagSet.StringSliceVarP(&options.IPFormats, "if", "ip-format", nil, "IP formats (0,1,2,3,4,5,6,7,8,9,10,11)", goflags.NormalizedStringSliceOptions),
		flagSet.IntVarP(&options.ZeroPadNumberOfZeroes, "zero-pad-n", "zpn", 3, "number of padded zero to use"),
		flagSet.BoolVarP(&options.ZeroPadPermute, "zero-pad-permute", "zpp", false, "enable permutations from 0 to zero-pad-n for each octets"),
	)

	// Filter
	flagSet.CreateGroup("filter", "Filter",
		flagSet.BoolVarP(&options.FilterIP4, "filter-ipv4", "f4", false, "Filter IPv4 IPs from input"),
		flagSet.BoolVarP(&options.FilterIP6, "filter-ipv6", "f6", false, "Filter IPv6 IPs from input"),
		flagSet.BoolVar(&options.SkipBaseIP, "skip-base", false, "Skip base IPs (ending in .0) in output"),
		flagSet.BoolVar(&options.SkipBroadcastIP, "skip-broadcast", false, "Skip broadcast IPs (ending in .255) in output"),
		flagSet.StringSliceVarP(&options.MatchIP, "match-ip", "mi", nil, "IP/CIDR/FILE containing list of IP/CIDR to match (comma-separated, file input)", goflags.FileNormalizedStringSliceOptions),
		flagSet.StringSliceVarP(&options.FilterIP, "filter-ip", "fi", nil, "IP/CIDR/FILE containing list of IP/CIDR to filter (comma-separated, file input)", goflags.FileNormalizedStringSliceOptions),
	)

	// Miscellaneous
	flagSet.CreateGroup("miscellaneous", "Miscellaneous",
		flagSet.BoolVarP(&options.SortAscending, "sort", "s", false, "Sort input IPs/CIDRs in ascending order"),
		flagSet.BoolVarP(&options.SortDescending, "sort-reverse", "sr", false, "Sort input IPs/CIDRs in descending order"),
		flagSet.BoolVarP(&options.Shuffle, "shuffle-ip", "si", false, "Shuffle Input IPs in random order"),
		flagSet.StringVarP(&options.ShufflePorts, "shuffle-port", "sp", "", "Shuffle Input IP:Port in random order"),
	)

	// Output
	flagSet.CreateGroup("output", "Output",
		flagSet.BoolVar(&options.Verbose, "verbose", false, "Verbose mode"),
		flagSet.StringVarP(&options.Output, "output", "o", "", "File to write output to"),
		flagSet.BoolVar(&options.Silent, "silent", false, "Silent mode"),
		flagSet.BoolVar(&options.Version, "version", false, "Show version of the project"),
	)

	if err := flagSet.Parse(); err != nil {
		gologger.Fatal().Msgf("%s\n", err)
	}

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

	// enable all ip encodings if "0" is specified
	if sliceutil.Contains(options.IPFormats, "0") {
		options.IPFormats = []string{"1", "2", "3", "4", "5", "6", "7", "8", "9", "10"}
	}

	if err := options.validateOptions(); err != nil {
		gologger.Fatal().Msgf("%s\n", err)
	}

	return options
}

func (options *Options) validateOptions() error {
	if options.FileCidr == nil && !fileutil.HasStdin() {
		return errors.New("no input provided")
	}

	if options.Slices > 0 && options.HostCount > 0 {
		return errors.New("sbc and sbh can't be used together")
	}

	if options.SortAscending && options.SortDescending {
		return errors.New("can sort only in one direction")
	}

	if options.FilterIP4 && options.FilterIP6 {
		return errors.New("IP4 and IP6 can't be used together")
	}

	if options.ToIP4 && options.ToIP6 {
		return errors.New("IP4 and IP6 can't be converted together")
	}
	if options.FilterIP != nil && options.MatchIP != nil {
		return errors.New("both match and filter mode specified")
	}
	return nil
}

// configureOutput configures the output on the screen
func (options *Options) configureOutput() {
	if options.Silent {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelSilent)
	} else if options.Verbose {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelWarning)
	}
}

var options *Options

func main() {
	options = ParseOptions()
	chancidr := make(chan string)
	outputchan := make(chan string)
	var wg sync.WaitGroup

	wg.Add(1)
	go process(&wg, chancidr, outputchan)
	wg.Add(1)
	go output(&wg, outputchan)

	if fileutil.HasStdin() {
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			_ = options.FileCidr.Set(scanner.Text())
		}
	}
	if options.FileCidr != nil {
		for _, item := range options.FileCidr {
			chancidr <- item
		}
	}
	close(chancidr)
	wg.Wait()
}

func filterIPsFromFlagList(channel chan string, ip string, ipFlagList []string) {
	if len(ipFlagList) == 0 {
		sendToOutputChannel(ip, channel)
		return
	}
	if options.MatchIP != nil {
		for _, item := range ipFlagList {
			if strings.EqualFold(ip, item) {
				sendToOutputChannel(ip, channel)
				break
			}
		}
	} else if options.FilterIP != nil {
		var contains = false
		for _, item := range ipFlagList {
			if ip == item {
				contains = true
			}
		}
		if !contains {
			sendToOutputChannel(ip, channel)
		}
	} else {
		sendToOutputChannel(ip, channel)
	}
}
func sendToOutputChannel(ip string, channel chan string) {
	ipnet := net.ParseIP(ip)
	switch {
	case options.ToIP4:
		if ip4 := ipnet.To4(); ip4 != nil {
			channel <- ip4.String()
		} else {
			channel <- ip
		}
	case options.ToIP6:
		if ip6 := ipnet.To16(); ip6 != nil {
			// check if it's ip4-mapped-ip6
			if ipnet.To4() != nil {
				channel <- mapcidr.FmtIP4MappedIP6(ip6)
			} else {
				channel <- ip6.String()
			}
		} else {
			gologger.Warning().Msgf("%s could not be mapped to IPv6\n", ip)
		}
	default:
		channel <- ip
	}
}
func prepareIPsFromCidrFlagList(items []string) []string {
	var flagIPList []string
	for _, item := range items {
		if _, pCidr, err := net.ParseCIDR(item); err == nil && pCidr != nil {
			if ips, err := mapcidr.IPAddressesAsStream(pCidr.String()); err == nil {
				for ip := range ips {
					flagIPList = append(flagIPList, ip)
				}
			}
		} else {
			flagIPList = append(flagIPList, item)
		}
	}
	return flagIPList
}
func process(wg *sync.WaitGroup, chancidr, outputchan chan string) {
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
		if ip := net.ParseIP(cidr); ip != nil {
			switch {
			case ip.To4() != nil:
				cidr += "/32"
			case ip.To16() != nil:
				cidr += "/128"
			}
		}
		// test if we have a cidr
		if _, pCidr, err = net.ParseCIDR(cidr); err != nil {
			gologger.Fatal().Msgf("%s\n", err)
		}

		// filters ip4|ip6, by default do not filter
		_, bits := pCidr.Mask.Size()
		isCidr4 := bits == mapcidr.DefaultMaskSize4
		isCidr6 := bits > mapcidr.DefaultMaskSize4
		isWrongIpType := (options.FilterIP4 && isCidr6) || (options.FilterIP6 && isCidr4)
		if isWrongIpType {
			continue
		}

		// In case of coalesce/shuffle we need to know all the cidrs and aggregate them by calling the proper function
		if options.Aggregate || options.Shuffle || hasSort || options.AggregateApprox || options.Count {
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
			var ipFlagList []string
			ipFlagList = append(ipFlagList, prepareIPsFromCidrFlagList(options.MatchIP)...)
			ipFlagList = append(ipFlagList, prepareIPsFromCidrFlagList(options.FilterIP)...)
			ips, err := mapcidr.IPAddressesAsStream(cidr)
			if err != nil {
				gologger.Fatal().Msgf("%s\n", err)
			}
			for ip := range ips {
				filterIPsFromFlagList(outputchan, ip, ipFlagList)
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

	if options.AggregateApprox {
		for _, cidr := range mapcidr.AggregateApproxIPV4s(allCidrs) {
			outputchan <- cidr.String()
		}
	}

	if options.Count {
		includeBase := !options.SkipBaseIP
		includeBroadcast := !options.SkipBroadcastIP
		ipSum := mapcidr.CountIPsInCIDRs(includeBase, includeBroadcast, allCidrs...)
		outputchan <- ipSum.String()
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

		if len(options.IPFormats) > 0 {
			outputItems(f, mapcidr.AlterIP(o, options.IPFormats, options.ZeroPadNumberOfZeroes, options.ZeroPadPermute)...)
		} else {
			outputItems(f, o)
		}
	}
}

func outputItems(f *os.File, items ...string) {
	for _, item := range items {
		gologger.Silent().Msgf("%s\n", item)
		if f != nil {
			_, _ = f.WriteString(item + "\n")
		}
	}
}
