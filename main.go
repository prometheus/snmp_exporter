package main

import (
  "fmt"
  "log"

  "github.com/soniah/gosnmp"
)

func getTable(target *gosnmp.GoSNMP, oid string) {
  results, err := gosnmp.Default.BulkWalkAll(oid)
  if err != nil {
    log.Fatalf("Get() err: %v", err)
  }

  for _, variable := range results {
    fmt.Printf("oid: %s ", variable.Name[len(oid) + 1:])

    // the Value of each variable returned by Get() implements
    // interface{}. You could do a type switch...
    switch variable.Type {
    case gosnmp.OctetString:
      fmt.Printf("string: %s\n", string(variable.Value.([]byte)))
    default:
      // ... or often you're just interested in numeric values.
      // ToBigInt() will return the Value as a BigInt, for plugging
      // into your calculations.
      fmt.Printf("number: %d\n", gosnmp.ToBigInt(variable.Value))
    }
  }
}

func main() {
  gosnmp.Default.Target = "127.0.0.1"
  err := gosnmp.Default.Connect()
  if err != nil {
    log.Fatalf("Connect() err: %v", err)
  }
  defer gosnmp.Default.Conn.Close()

  oid := ".1.3.6.1.2.1.2.2.1.10"
  getTable(gosnmp.Default, oid)

}
