// Copyright The Prometheus Authors
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

package main

import (
	"fmt"

	"github.com/prometheus/snmp_exporter/config"
)

// generateFingerprinters returns a copy of fps with all matcher OIDs, which
// may be MIB names, resolved to numeric OIDs.
func generateFingerprinters(fps map[string]*config.Fingerprinter, nameToNode map[string]*Node) (map[string]*config.Fingerprinter, error) {
	if len(fps) == 0 {
		return nil, nil
	}
	out := make(map[string]*config.Fingerprinter, len(fps))
	for name, fp := range fps {
		if fp == nil {
			return nil, fmt.Errorf("fingerprinter %q is empty", name)
		}
		outFp := &config.Fingerprinter{
			DiscoveryModules: fp.DiscoveryModules,
			DefaultModules:   fp.DefaultModules,
		}
		for i, m := range fp.Matchers {
			if m == nil {
				return nil, fmt.Errorf("fingerprinter %q: matcher %d is empty", name, i)
			}
			outM := *m
			oid, err := resolveOid(m.Oid, nameToNode)
			if err != nil {
				return nil, fmt.Errorf("fingerprinter %q: matcher %d: %w", name, i, err)
			}
			outM.Oid = oid
			outFp.Matchers = append(outFp.Matchers, &outM)
		}
		out[name] = outFp
	}
	return out, nil
}

func resolveOid(name string, nameToNode map[string]*Node) (string, error) {
	if n, ok := nameToNode[name]; ok {
		return n.Oid, nil
	}
	if config.IsNumericOid(name) {
		return name, nil
	}
	return "", fmt.Errorf("cannot find oid %q", name)
}
