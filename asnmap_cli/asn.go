package asnmap_cli

import (
	"fmt"

	asnmap "github.com/projectdiscovery/asnmap/libs"
)

func UseASN() {
	client := asnmap.NewClient()

	// Query based on ASN
	asn := "14421"
	ASN := asnmap.ASN(asn)
	results := asnmap.GetFormattedDataInJson(client.GetData(ASN))
	fmt.Println(string(results))
}
