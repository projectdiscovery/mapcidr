
<h1 align="center">
  <img src="static/mapCIDR-logo.png" alt="mapCIDR" width="180px"></a>
  <br>
</h1>

<h4 align="center">A utility program to perform multiple operations for a given subnet/cidr ranges.</h4>


<p align="center">
<a href="https://github.com/projectdiscovery/mapcidr/issues"><img src="https://img.shields.io/badge/contributions-welcome-brightgreen.svg?style=flat"></a>
<a href="https://github.com/projectdiscovery/mapcidr/releases"><img src="https://img.shields.io/github/release/projectdiscovery/mapcidr"></a>
<a href="https://twitter.com/pdiscovery"><img src="https://img.shields.io/twitter/follow/pdnuclei.svg?logo=twitter"></a>
<a href="https://discord.gg/projectdiscovery"><img src="https://img.shields.io/discord/695645237418131507.svg?logo=discord"></a>
</p>
      
<p align="center">
  <a href="#features">Features</a> •
  <a href="#installation">Install</a> •
  <a href="#running-mapcidr">Usage</a> •
  <a href="#use-mapcidr-as-a-library">Library</a> •
  <a href="https://discord.gg/projectdiscovery">Join Discord</a>
</p>

----

mapCIDR is developed to ease load distribution for mass scanning operations, it can be used both as a library and as independent CLI tool.

# Features

<h1 align="left">
  <img src="static/mapCIDR-run.png" alt="mapCIDR" width="700px"></a>
  <br>
</h1>

 - CIDR expansion support
 - CIDR slicing support
 - CIDR/IP aggregation support
 - CIDR based IP filter support
 - STD IN/OUT support

# Installation

```sh
▶ GO111MODULE=on go get -v github.com/projectdiscovery/mapcidr/cmd/mapcidr
```

# Usage

```sh
▶ mapcidr -h
```

This will display help for the tool. Here are all the switches it supports.

| Flag      | Description                             | Example                     |
| --------- | --------------------------------------- | --------------------------- |
| aggregate | Aggregate CIDRs into the minimum number | mapcidr -aggregate          |
| cidr      | Single CIDR to process                  | mapcidr -cidr 173.0.84.0/24 |
| ips       | File containing ips to process          | mapcidr -ips ips.txt        |
| sbc       | Slice by CIDR count                     | mapcidr -sbc 10             |
| sbh       | Slice by HOST count                     | mapcidr -sbh 10000          |
| l         | File containing list of CIDRs           | mapcidr -l cidr.txt         |
| o         | File to write output to (optional)      | mapcidr -o output.txt       |
| silent    | Make the output silent                  | mapcidr -silent             |
| version   | Print current version of mapcidr client | mapcidr -version            |

# Running mapCIDR

In order to get list of IPs for a give CIDR, use the following command.

```sh
▶ mapcidr -cidr 173.0.84.0/24
▶ echo 173.0.84.0/24 | mapcidr

```

```sh
                   ____________  ___    
  __ _  ___ ____  / ___/  _/ _ \/ _ \
 /  ' \/ _ '/ _ \/ /___/ // // / , _/   
/_/_/_/\_,_/ .__/\___/___/____/_/|_| v0.5
          /_/                                                     	 

		projectdiscovery.io

[WRN] Use with caution. You are responsible for your actions
[WRN] Developers assume no liability and are not responsible for any misuse or damage.

173.0.84.0
173.0.84.1
173.0.84.2
173.0.84.3
173.0.84.4
173.0.84.5
173.0.84.13
173.0.84.14
173.0.84.15
173.0.84.16
```

### Slice by CIDR 

In order to slice given CIDR or list of CIDR by CIDR count or slice into multiple and equal smaller subnets, use the following command.


```sh
▶ mapcidr -cidr 173.0.84.0/24 -sbc 10 -silent
▶ echo 173.0.84.0/24 | mapcidr -sbc 10 -silent
```

```
173.0.84.0/27
173.0.84.32/27
173.0.84.64/27
173.0.84.96/27
173.0.84.128/27
173.0.84.160/27
173.0.84.208/28
173.0.84.192/28
173.0.84.240/28
173.0.84.224/28
```

### Slice by HOST 

In order to slice given CIDR for equal number of host count in each CIDR, use the following command.

```sh
▶ mapcidr -cidr 173.0.84.0/16 -sbh 20000 -silent
▶ echo 173.0.84.0/16 | mapcidr -sbh 20000 -silent
```

```
173.0.0.0/18
173.0.64.0/18
173.0.128.0/18
173.0.192.0/18
```

Note: it's possible to obtain a perfect split only when the desired amount of slices or hosts per subnet is a powers of two. Otherwise the tool will attempt to automatically find the best split strategy to obtain the desired outcome. 

# Use mapCIDR as a library

It's possible to use the library directly in your go programs. The following code snippets outline how to divide a cidr into subnets, and how to divide the same into subnets containing a certain number of hosts

```go
package main

import (
	"fmt"

	"github.com/projectdiscovery/mapcidr"
)

func main() {
	// Divide the CIDR into two subnets
	subnets1 := mapcidr.SplitN("192.168.1.0/24", 2)
	for _, subnet := range subnets1 {
		fmt.Println(subnet)
	}
	// Divide the CIDR into two subnets containing 128 hosts each
	subnets2 := mapcidr.SplitByNumber("192.168.1.0/24", 128)
	for _, subnet := range subnets2 {
		fmt.Println(subnet)
	}

	// List all ips in the CIDR
	ips, _ := mapcidr.IPAddresses("192.168.1.0/24")
	for _, ip := range ips {
		fmt.Println(ip)
	}
}

```


mapCDIR is made with 🖤 by the [projectdiscovery](https://projectdiscovery.io) team.
