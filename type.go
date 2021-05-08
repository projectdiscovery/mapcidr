package mapcidr

import (
	"fmt"
	"net"
)

type Item struct {
	IP   string
	Port int
}

func (i Item) String() string {
	return net.JoinHostPort(i.IP, fmt.Sprintf("%d", i.Port))
}
