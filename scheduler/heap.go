// Copyright 2026 The Prometheus Authors
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

package scheduler

import "container/heap"

type deviceHeap []*deviceState

func (h deviceHeap) Len() int { return len(h) }

func (h deviceHeap) Less(i, j int) bool {
	if h[i].nextRun.Equal(h[j].nextRun) {
		return h[i].device.ID < h[j].device.ID
	}
	return h[i].nextRun.Before(h[j].nextRun)
}

func (h deviceHeap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
	h[i].heapIndex = i
	h[j].heapIndex = j
}

func (h *deviceHeap) Push(value any) {
	state := value.(*deviceState)
	state.heapIndex = len(*h)
	*h = append(*h, state)
}

func (h *deviceHeap) Pop() any {
	old := *h
	last := len(old) - 1
	state := old[last]
	old[last] = nil
	state.heapIndex = -1
	*h = old[:last]
	return state
}

func (h *deviceHeap) remove(state *deviceState) {
	if state.heapIndex >= 0 {
		heap.Remove(h, state.heapIndex)
	}
}

func (h *deviceHeap) schedule(state *deviceState) {
	if state.heapIndex >= 0 {
		heap.Fix(h, state.heapIndex)
		return
	}
	heap.Push(h, state)
}
