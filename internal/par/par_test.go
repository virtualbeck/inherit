package par

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestEachRunsEveryItemWithinLimit(t *testing.T) {
	items := make([]int, 50)
	for i := range items {
		items[i] = i
	}
	var (
		inFlight, peak atomic.Int32
		mu             sync.Mutex
		seen           = map[int]bool{}
	)
	Each(items, 4, func(i int) {
		n := inFlight.Add(1)
		for {
			p := peak.Load()
			if n <= p || peak.CompareAndSwap(p, n) {
				break
			}
		}
		time.Sleep(time.Millisecond)
		inFlight.Add(-1)
		mu.Lock()
		seen[i] = true
		mu.Unlock()
	})
	if len(seen) != len(items) {
		t.Fatalf("ran %d of %d items", len(seen), len(items))
	}
	if p := peak.Load(); p > 4 {
		t.Fatalf("peak concurrency %d exceeds limit 4", p)
	}
}

func TestEachEmptyAndUnbounded(t *testing.T) {
	Each[int](nil, 8, func(int) { t.Fatal("called on empty input") })
	var n atomic.Int32
	Each([]int{1, 2, 3}, 0, func(int) { n.Add(1) })
	if n.Load() != 3 {
		t.Fatalf("unbounded: ran %d of 3", n.Load())
	}
}
