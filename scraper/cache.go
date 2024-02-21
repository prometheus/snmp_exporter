// Copyright 2024 The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package scraper

import "github.com/gosnmp/gosnmp"

type cacheClient struct {
	scraper     SNMPScraper
	walkResults map[string][]gosnmp.SnmpPDU
}

func NewCacheClient(scraper SNMPScraper) *cacheClient {
	return &cacheClient{
		scraper:     scraper,
		walkResults: make(map[string][]gosnmp.SnmpPDU),
	}
}

func (c *cacheClient) Get(oids []string) (*gosnmp.SnmpPacket, error) {
	return c.scraper.Get(oids)
}

func (c *cacheClient) WalkAll(oid string) ([]gosnmp.SnmpPDU, error) {
	if result, ok := c.walkResults[oid]; ok {
		return result, nil
	}
	results, err := c.scraper.WalkAll(oid)
	if err == nil {
		c.walkResults[oid] = results
	}
	return results, err
}

func (c *cacheClient) Connect() error {
	return c.scraper.Connect()
}

func (c *cacheClient) Close() error {
	return c.scraper.Close()
}

func (c *cacheClient) SetOptions(fns ...func(*gosnmp.GoSNMP)) {
	c.scraper.SetOptions(fns...)
}
