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
	"testing"
	"testing/synctest"

	"github.com/prometheus/common/model"
	"github.com/prometheus/prometheus/discovery/targetgroup"
)

type fakeDiscoverer struct {
	ch chan<- []*targetgroup.Group
}

func (f *fakeDiscoverer) Run(_ context.Context, up chan<- []*targetgroup.Group) {
	f.ch = up
}

func TestTrackTargets(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		d := &fakeDiscoverer{}
		mgr := NewManaged(d)
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		go mgr.Run(ctx)
		synctest.Wait()
		if d.ch == nil {
			t.Error("discovery was never started")
		}

		// targets added should propagate to manager
		d.ch <- []*targetgroup.Group{
			{
				Targets: []model.LabelSet{
					{
						model.AddressLabel: "test",
					},
				},
				Labels: model.LabelSet{
					"foo": "bar",
				},
				Source: "test",
			},
		}
		synctest.Wait()

		if len(mgr.targets) != 1 || mgr.targets["test"] == nil {
			t.Error("target not propagated to manager")
		}

		// adding the same target again should not increase number of targets
		d.ch <- []*targetgroup.Group{
			{
				Targets: []model.LabelSet{
					{
						model.AddressLabel: "test",
					},
				},
				Labels: model.LabelSet{
					"foo": "bar",
				},
				Source: "test",
			},
		}
		synctest.Wait()

		if len(mgr.targets) != 1 || mgr.targets["test"] == nil {
			t.Error("target not propagated to manager")
		}
		// adding another source should append to target store
		d.ch <- []*targetgroup.Group{
			{
				Targets: []model.LabelSet{
					{
						model.AddressLabel: "another-test",
					},
				},
				Labels: model.LabelSet{
					"foo": "bar",
				},
				Source: "another-test",
			},
		}
		synctest.Wait()

		if len(mgr.targets) != 2 || mgr.targets["another-test"] == nil {
			t.Error("second target not propagated to manager")
		}

		// sending an empty target list should remove it from the target store
		d.ch <- []*targetgroup.Group{
			{
				Source: "another-test",
			},
		}
		synctest.Wait()

		if len(mgr.targets) != 1 || mgr.targets["another-test"] != nil {
			t.Error("second target not deleted")
		}

		// addition & deletion in the same update
		d.ch <- []*targetgroup.Group{
			{
				Source: "test",
			},
			{
				Targets: []model.LabelSet{
					{
						model.AddressLabel: "yet-another-test",
					},
				},
				Labels: model.LabelSet{
					"foo": "bar",
				},
				Source: "yet-another-test",
			},
		}
		synctest.Wait()

		if len(mgr.targets) != 1 || mgr.targets["yet-another-test"] == nil {
			t.Error("update not applied correctly")
		}
	})
}
