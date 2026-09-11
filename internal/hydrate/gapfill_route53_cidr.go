package hydrate

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	"github.com/virtualbeck/inherit/model"
)

func init() { registerGlobalGapFiller(gapFillRoute53CIDRCollections) }

// gapFillRoute53CIDRCollections discovers CIDR collections (used by
// aws_route53_record's cidr_routing_policy) and the CIDR blocks grouped
// under each of their named locations -- a global Route53 feature, no ARN
// tagging concept for either type.
func gapFillRoute53CIDRCollections(ctx context.Context, c *Clients, _ string) ([]model.Resource, error) {
	cl := route53.NewFromConfig(c.Cfg(""))
	var out []model.Resource
	token := (*string)(nil)
	for {
		page, err := cl.ListCidrCollections(ctx, &route53.ListCidrCollectionsInput{NextToken: token})
		if err != nil {
			return out, nil
		}
		for _, col := range page.CidrCollections {
			id := aws.ToString(col.Id)
			name := aws.ToString(col.Name)
			if id == "" || name == "" {
				continue
			}
			out = append(out, model.Resource{
				Service: "route53", Type: "cidr-collection", TFType: "aws_route53_cidr_collection",
				ID: id, ImportID: id,
				Config: map[string]any{"name": name},
			})
			out = append(out, route53CIDRLocations(ctx, cl, id)...)
		}
		if page.NextToken == nil {
			break
		}
		token = page.NextToken
	}
	return out, nil
}

// route53CIDRLocations groups one collection's CIDR blocks by location name
// -- ListCidrBlocks returns a flat {cidr_block, location_name} list, but the
// schema wants one aws_route53_cidr_location per location with a set of its
// blocks.
func route53CIDRLocations(ctx context.Context, cl *route53.Client, collectionID string) []model.Resource {
	byLocation := map[string][]string{}
	var order []string
	token := (*string)(nil)
	for {
		page, err := cl.ListCidrBlocks(ctx, &route53.ListCidrBlocksInput{CollectionId: &collectionID, NextToken: token})
		if err != nil {
			break
		}
		for _, b := range page.CidrBlocks {
			loc := aws.ToString(b.LocationName)
			cidr := aws.ToString(b.CidrBlock)
			if loc == "" || cidr == "" {
				continue
			}
			if _, ok := byLocation[loc]; !ok {
				order = append(order, loc)
			}
			byLocation[loc] = append(byLocation[loc], cidr)
		}
		if page.NextToken == nil {
			break
		}
		token = page.NextToken
	}
	var out []model.Resource
	for _, loc := range order {
		id := collectionID + "," + loc
		out = append(out, model.Resource{
			Service: "route53", Type: "cidr-location", TFType: "aws_route53_cidr_location",
			ID: id, ImportID: id,
			Config: map[string]any{
				"cidr_collection_id": collectionID,
				"name":               loc,
				"cidr_blocks":        toAny(byLocation[loc]),
			},
		})
	}
	return out
}
