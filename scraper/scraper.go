package scraper

import (
	"github.com/gosnmp/gosnmp"
)

type SNMPScraper interface {
	Get([]string) (*gosnmp.SnmpPacket, error)
	WalkAll(string) ([]gosnmp.SnmpPDU, error)
	Connect() error
	Close() error
	SetOptions(...func(*gosnmp.GoSNMP))
}
