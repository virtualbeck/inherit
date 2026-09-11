// Package discover builds the account resource inventory with the Resource
// Groups Tagging API, swept across regions concurrently. Read-only.
package discover

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/resourcegroupstaggingapi"
	rgttypes "github.com/aws/aws-sdk-go-v2/service/resourcegroupstaggingapi/types"
	"github.com/virtualbeck/inherit/model"
)

// Options controls a sweep.
type Options struct {
	Account          string
	Partition        string
	Regions          []string
	Concurrency      int  // max regions swept at once
	IncludeEphemeral bool // keep snapshots / images / sessions / recovery points
	// Exclude entries are either a bare service namespace ("cloudformation",
	// dropping every resource of that service) or "service:type" (e.g.
	// "cloudformation:stackset", dropping just that one ARN resource-type
	// within the service -- the type string is the ARN's own resource-type
	// segment, case-insensitive; see a scan's own inventory.json / discovered-
	// types summary if unsure what a given type is called).
	Exclude []string
	// Services, when non-empty, is an allowlist: only resources whose ARN
	// service segment is in this list are kept, before Exclude is applied.
	// Coarser than Exclude in the opposite direction -- for scanning one or
	// two services out of a large, messy account instead of excluding
	// everything else by name.
	Services []string
	OnRegion func(region string, found int, err error)
}

// ephemeral is the set of (service, ARN resource-type) pairs inherit drops from
// the inventory by default: backups / snapshots / point-in-time artifacts /
// transient sessions that never belong in IaC, plus a few types that inherit
// already emits from a parent's fanout (so the standalone ARN is a duplicate).
// Kept when IncludeEphemeral is set.
var ephemeral = map[[2]string]bool{
	{"ec2", "snapshot"}:                            true, // EBS snapshots
	{"ec2", "image"}:                               true, // AMIs
	{"ec2", "spot-instances-request"}:              true,
	{"ec2", "security-group-rule"}:                 true, // emitted via the aws_security_group fanout
	{"elasticloadbalancing", "listener-rule"}:      true, // emitted via the aws_lb_listener fanout
	{"application-autoscaling", "scalable-target"}: true, // emitted via the app-autoscaling gap-filler
	{"rds", "snapshot"}:                            true,
	{"rds", "cluster-snapshot"}:                    true,
	{"backup", "recovery-point"}:                   true,
	{"elasticache", "snapshot"}:                    true,
	{"redshift", "snapshot"}:                       true,
	{"dynamodb", "backup"}:                         true,
	{"ssm", "session"}:                             true,
	{"ssm", "automation-execution"}:                true,
	{"ssm", "managed-instance"}:                    true,
	{"athena", "query-execution"}:                  true,
	{"glue", "job-run"}:                            true,
	{"sagemaker", "processing-job"}:                true,
	{"sagemaker", "training-job"}:                  true,
	{"sagemaker", "transform-job"}:                 true,
	{"cloudformation", "changeSet"}:                true,
}

// IsEphemeral reports whether a discovered resource is a backup / snapshot /
// session artifact that inherit skips by default.
func IsEphemeral(r model.Resource) bool { return ephemeral[[2]string{r.Service, r.Type}] }

// filterResources applies --services (if given), --exclude, and (unless
// includeEphemeral) the ephemeral denylist to one region's raw results,
// reporting how many were dropped by --services/--exclude combined.
func filterResources(res []model.Resource, allow map[string]bool, excludedServices map[string]bool, excludedTypes map[[2]string]bool, includeEphemeral bool) ([]model.Resource, int) {
	var kept []model.Resource
	var excludedHits int
	for _, r := range res {
		svc := strings.ToLower(r.Service)
		if allow != nil && !allow[svc] {
			excludedHits++
			continue
		}
		if excludedServices[svc] || excludedTypes[[2]string{svc, strings.ToLower(r.Type)}] {
			excludedHits++
			continue
		}
		if !includeEphemeral && IsEphemeral(r) {
			continue
		}
		kept = append(kept, r)
	}
	return kept, excludedHits
}

// excludeSet splits --exclude entries into whole-service and service:type
// denylists, lower-cased for case-insensitive matching.
func excludeSet(entries []string) (services map[string]bool, types map[[2]string]bool) {
	for _, e := range entries {
		e = strings.ToLower(strings.TrimSpace(e))
		if e == "" {
			continue
		}
		if svc, typ, ok := strings.Cut(e, ":"); ok {
			if types == nil {
				types = map[[2]string]bool{}
			}
			types[[2]string{svc, typ}] = true
			continue
		}
		if services == nil {
			services = map[string]bool{}
		}
		services[e] = true
	}
	return services, types
}

// servicesAllowSet lower-cases and set-ifies a --services allowlist.
func servicesAllowSet(services []string) map[string]bool {
	if len(services) == 0 {
		return nil
	}
	set := make(map[string]bool, len(services))
	for _, s := range services {
		set[strings.ToLower(strings.TrimSpace(s))] = true
	}
	return set
}

// Sweep enumerates every taggable resource across the given regions. Resources
// with no region in their ARN (global services such as IAM) are de-duplicated
// so they appear once.
//
// Returns the inventory, the count skipped as ephemeral, and the count
// skipped because their service is in Exclude.
func Sweep(ctx context.Context, cfg aws.Config, opt Options) (model.Inventory, int, int, error) {
	if opt.Concurrency <= 0 {
		opt.Concurrency = 8
	}
	allow := servicesAllowSet(opt.Services)
	excludedServices, excludedTypes := excludeSet(opt.Exclude)

	var (
		mu           sync.Mutex
		byARN        = map[string]model.Resource{}
		errs         []error
		skipped      int
		excludedHits int
		sem          = make(chan struct{}, opt.Concurrency)
		wg           sync.WaitGroup
	)

	for _, region := range opt.Regions {
		region := region
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()

			res, err := sweepRegion(ctx, cfg, region)
			kept, excludedInRegion := filterResources(res, allow, excludedServices, excludedTypes, opt.IncludeEphemeral)
			if opt.OnRegion != nil {
				opt.OnRegion(region, len(kept), err)
			}
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", region, err))
				return
			}
			excludedHits += excludedInRegion
			skipped += len(res) - excludedInRegion - len(kept)
			for _, r := range kept {
				if existing, ok := byARN[r.ARN]; ok {
					// global resource seen from a second region - keep the first
					_ = existing
					continue
				}
				byARN[r.ARN] = r
			}
		}()
	}
	wg.Wait()

	inv := model.Inventory{
		Account:   opt.Account,
		Partition: opt.Partition,
		Regions:   append([]string(nil), opt.Regions...),
		Resources: make([]model.Resource, 0, len(byARN)),
	}
	for _, r := range byARN {
		inv.Resources = append(inv.Resources, r)
	}
	sort.Slice(inv.Resources, func(i, j int) bool { return inv.Resources[i].ARN < inv.Resources[j].ARN })

	if len(inv.Resources) == 0 && len(errs) > 0 {
		return inv, skipped, excludedHits, fmt.Errorf("discovery failed in every region: %v", errs[0])
	}
	return inv, skipped, excludedHits, nil
}

func sweepRegion(ctx context.Context, cfg aws.Config, region string) ([]model.Resource, error) {
	c := resourcegroupstaggingapi.NewFromConfig(cfg, func(o *resourcegroupstaggingapi.Options) {
		o.Region = region
	})
	p := resourcegroupstaggingapi.NewGetResourcesPaginator(c, &resourcegroupstaggingapi.GetResourcesInput{
		ResourcesPerPage: aws.Int32(100),
	})

	var out []model.Resource
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, m := range page.ResourceTagMappingList {
			if r, ok := toResource(m); ok {
				out = append(out, r)
			}
		}
	}
	return out, nil
}

func toResource(m rgttypes.ResourceTagMapping) (model.Resource, bool) {
	arn := aws.ToString(m.ResourceARN)
	partition, service, region, account, resource, ok := model.ParseARN(arn)
	if !ok {
		return model.Resource{}, false
	}
	// apigateway ARNs are arn:aws:apigateway:region::/restapis/<id>; the leading
	// slash would otherwise swallow the resource type.
	resource = strings.TrimPrefix(resource, "/")
	rtype, id := model.SplitResource(resource)
	r := model.Resource{
		ARN:     arn,
		Service: service,
		Type:    rtype,
		Region:  region,
		Account: account,
		ID:      id,
	}
	_ = partition
	for _, t := range m.Tags {
		k := aws.ToString(t.Key)
		// aws:* tags are system-managed (CloudFormation, ControlTower, ...); the
		// provider never puts them in state, so emitting them is pure drift.
		if strings.HasPrefix(k, "aws:") {
			continue
		}
		if r.Tags == nil {
			r.Tags = map[string]string{}
		}
		r.Tags[k] = aws.ToString(t.Value)
	}
	return r, true
}
