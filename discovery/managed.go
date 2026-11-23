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
	"context"
	"encoding/json"
	"maps"
	"net/http"
	"slices"
	"strings"

	promdisco "github.com/prometheus/prometheus/discovery"
	"github.com/prometheus/prometheus/discovery/targetgroup"
)

type Managed struct {
	d       promdisco.Discoverer
	targets map[string]*targetgroup.Group
}

func NewManaged(d promdisco.Discoverer) *Managed {
	return &Managed{
		d:       d,
		targets: make(map[string]*targetgroup.Group),
	}
}

func (m *Managed) Run(ctx context.Context) {
	c := make(chan []*targetgroup.Group)
	go m.d.Run(ctx, c)
	for {
		select {
		case <-ctx.Done():
			return
		case up := <-c:
			for _, t := range up {
				if len(t.Targets) == 0 {
					delete(m.targets, t.Source)
				} else {
					m.targets[t.Source] = t
				}
			}
		}
	}
}

func (m *Managed) Handle(w http.ResponseWriter, _ *http.Request) {
	groups := slices.Collect(maps.Values(m.targets))

	// technically not needed but makes the output consistent & easier to debug
	slices.SortFunc(groups, func(a, b *targetgroup.Group) int {
		return strings.Compare(a.Source, b.Source)
	})

	w.Header().Add("content-type", "application/json")
	if err := json.NewEncoder(w).Encode(groups); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
