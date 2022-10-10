package mapcidr

import (
	"fmt"

	asnmap "github.com/projectdiscovery/asnmap/libs"
)

func useASN(value string) {
	asn := asnmap.ASN(value[2:]) // drop AS from the value
	fmt.Println(asn)
}
