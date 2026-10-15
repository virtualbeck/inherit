// Package par runs bounded concurrent work.
package par

import "sync"

// Each runs fn on items, limit at once.
func Each[T any](items []T, limit int, fn func(T)) {
	if limit <= 0 || limit > len(items) {
		limit = len(items)
	}
	if limit == 0 {
		return
	}
	sem := make(chan struct{}, limit)
	var wg sync.WaitGroup
	for _, it := range items {
		sem <- struct{}{}
		wg.Go(func() {
			defer func() { <-sem }()
			fn(it)
		})
	}
	wg.Wait()
}
