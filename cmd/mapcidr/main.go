package main

import (
	"bufio"
	"flag"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/projectdiscovery/ipranger"
	"github.com/projectdiscovery/mapcidr"
)

// Options contains cli options
type Options struct {
	FileIps      string
	Slices       int
	HostCount    int
	Cidr         string
	FileCidr     string
	Silent       bool
	Version      bool
	Output       string
	Aggregate    bool
	Shuffle      bool
	ShufflePorts string
	// NoColor   bool
	// Verbose   bool
}

const banner = `
                   ____________  ___    
  __ _  ___ ____  / ___/  _/ _ \/ _ \   
 /  ' \/ _ '/ _ \/ /___/ // // / , _/   
/_/_/_/\_,_/ .__/\___/___/____/_/|_| v0.0.5
          /_/                                                     	 
`

// Version is the current version of mapcidr
const Version = `0.0.5`

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

	flag.StringVar(&options.FileIps, "ips", "", "File containing ips to process")
	flag.BoolVar(&options.Aggregate, "aggregate", false, "Aggregate CIDRs into the minimum number")
	flag.IntVar(&options.Slices, "sbc", 0, "Slice by CIDR count")
	flag.IntVar(&options.HostCount, "sbh", 0, "Slice by HOST count")
	flag.StringVar(&options.Cidr, "cidr", "", "Single CIDR to process")
	flag.StringVar(&options.FileCidr, "l", "", "File containing CIDR")
	flag.StringVar(&options.Output, "o", "", "File to write output to (optional)")
	flag.BoolVar(&options.Silent, "silent", false, "Silent mode")
	flag.BoolVar(&options.Shuffle, "shuffle", false, "Shuffle Ips")
	flag.StringVar(&options.ShufflePorts, "shuffle-ports", "", "Shuffle Ips with ports")
	flag.BoolVar(&options.Version, "version", false, "Show version")
	flag.Parse()

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
	if options.Cidr == "" && !hasStdin() && options.FileCidr == "" {
		gologger.Fatal().Msgf("No input provided!\n")
	}

	if options.Slices > 0 && options.HostCount > 0 {
		gologger.Fatal().Msgf("sbc and sbh cant be used together!\n")
	}

	if options.Cidr != "" && options.FileCidr != "" {
		gologger.Fatal().Msgf("CIDR and List input cant be used together!\n")
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

	if hasStdin() {
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
		defer file.Close()
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
		defer file.Close()
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
		if options.Aggregate || options.FileIps != "" || options.Shuffle {
			ranger.AddIPNet(pCidr)
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
			ips, err := mapcidr.IPAddresses(cidr)
			if err != nil {
				gologger.Fatal().Msgf("%s\n", err)
			}
			for _, ip := range ips {
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
		defer f.Close()
	}
	for o := range outputchan {
		if o == "" {
			continue
		}
		gologger.Silent().Msgf("%s\n", o)
		if f != nil {
			f.WriteString(o + "\n")
		}
	}
}

func hasStdin() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	if fi.Mode()&os.ModeNamedPipe == 0 {
		return false
	}
	return true
}
