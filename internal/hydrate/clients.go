package hydrate

import (
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
)

// Clients hands hydrators a region-pinned aws.Config, cached so a 40-subnet
// account doesn't rebuild the base config 40 times.
type Clients struct {
	base aws.Config
	mu   sync.Mutex
	byRg map[string]aws.Config
}

func newClients(cfg aws.Config) *Clients {
	return &Clients{base: cfg, byRg: map[string]aws.Config{}}
}

// Cfg returns the shared config pinned to region (or the base config for global
// services when region is "").
func (c *Clients) Cfg(region string) aws.Config {
	if region == "" {
		return c.base
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if cfg, ok := c.byRg[region]; ok {
		return cfg
	}
	cfg := c.base.Copy()
	cfg.Region = region
	c.byRg[region] = cfg
	return cfg
}
