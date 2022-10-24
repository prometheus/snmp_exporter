package main

import (
	"fmt"
	"log"
	"net"
	"time"

	gosnmp "github.com/gosnmp/gosnmp"
)

func main() {
	log.Println("Starting")

	var port uint16 = 2162
	go Start(fmt.Sprintf("tcp://0.0.0.0:%d", port))

	gosnmp.Default.Target = "127.0.0.1"
	gosnmp.Default.Transport = "tcp"
	gosnmp.Default.Port = port
	gosnmp.Default.Community = "public"
	gosnmp.Default.Version = gosnmp.Version1
	time.Sleep(time.Duration(1) * time.Second)

	oid := gosnmp.SnmpPDU{
		Name:  "1.3.6.1.2.1.1.6",
		Type:  gosnmp.ObjectIdentifier,
		Value: "1.3.6.1.2.1.1.6.10",
	}
	oid1 := gosnmp.SnmpPDU{
		Name:  "1.3.6.1.2.1.1.7",
		Type:  gosnmp.OctetString,
		Value: "Testing TCP trap...",
	}
	oid2 := gosnmp.SnmpPDU{
		Name:  "1.3.6.1.2.1.1.8",
		Type:  gosnmp.Integer,
		Value: 123,
	}

	cou := 5
	for cou > 0 {
		time.Sleep(time.Duration(1) * time.Second)
		err := gosnmp.Default.Connect()
		if err != nil {
			log.Fatal(err)
		}
		defer gosnmp.Default.Conn.Close()
		//RebuildCron()
		log.Printf("Running (%d)\n", cou)

		trap := gosnmp.SnmpTrap{
			Variables:    []gosnmp.SnmpPDU{oid, oid1, oid2},
			Enterprise:   ".1.3.6.1.6.3.1.1.5.1",
			AgentAddress: "127.0.0.1",
			GenericTrap:  0,
			SpecificTrap: 0,
			Timestamp:    300,
		}
		_, err = gosnmp.Default.SendTrap(trap)
		if err != nil {
			log.Fatalf("SendTrap() err: %v\n", err)
		}

		cou--
	}
	//time.Sleep(time.Duration(10) * time.Second)

	log.Println("Stop...")
}

// Start SNMP server
func Start(address string) {

	log.Printf("Starting SNMP TRAP Server on: %s\n", address)
	tl := gosnmp.NewTrapListener()
	tl.OnNewTrap = myTrapHandlerTCP
	tl.Params = gosnmp.Default

	err := tl.Listen(address)
	if err != nil {
		time.Sleep(1 * time.Second)
		log.Fatalf("Error in TRAP listen: %s\n", err)
	}
}

func myTrapHandlerTCP(packet *gosnmp.SnmpPacket, addr *net.UDPAddr) {
	log.Printf("SNMP trap received from: %s:%d. Community:%s, SnmpVersion:%s\n",
		addr.IP, addr.Port, packet.Community, packet.Version)
	for i, variable := range packet.Variables {
		var val string
		switch variable.Type {
		case gosnmp.OctetString:
			val = string(variable.Value.([]byte))
		case gosnmp.ObjectIdentifier:
			val = fmt.Sprintf("%s", variable.Value)
		case gosnmp.TimeTicks:
			a := gosnmp.ToBigInt(variable.Value)
			val = fmt.Sprintf("%d", (*a).Int64())
		case gosnmp.Null:
			val = ""
		default:
			// ... or often you're just interested in numeric values.
			// ToBigInt() will return the Value as a BigInt, for plugging
			// into your calculations.
			a := gosnmp.ToBigInt(variable.Value)
			val = fmt.Sprintf("%d", (*a).Int64())
		}
		log.Printf("- oid[%d]: %s (%s) = %v \n", i, variable.Name, variable.Type, val)

	}
}
