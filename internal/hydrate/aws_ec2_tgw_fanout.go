package hydrate

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/virtualbeck/inherit/model"
)

func init() {
	registerFanout("aws_ec2_transit_gateway_route_table", fanoutTGWRouteTable)
}

// fanoutTGWRouteTable expands a transit gateway route table into its static
// routes, associations, and propagations -- each a separate top-level
// resource in the provider.
func fanoutTGWRouteTable(ctx context.Context, c *Clients, parent model.Resource) ([]model.Resource, error) {
	cl := ec2.NewFromConfig(c.Cfg(parent.Region))
	rtID := parent.ID

	var kids []model.Resource

	// aws_ec2_transit_gateway_route only manages *static* routes -- routes
	// learned via BGP/attachment propagation aren't declarable through it at
	// all (the resource's schema has no "type" attribute), so propagated
	// ones must be filtered out here rather than left for the schema to
	// reject at plan time.
	var routeToken *string
	for {
		out, err := cl.SearchTransitGatewayRoutes(ctx, &ec2.SearchTransitGatewayRoutesInput{
			TransitGatewayRouteTableId: &rtID,
			Filters:                    []ec2types.Filter{{Name: aws.String("type"), Values: []string{"static"}}},
			NextToken:                  routeToken,
		})
		if err != nil {
			return kids, err
		}
		for _, route := range out.Routes {
			cidr := aws.ToString(route.DestinationCidrBlock)
			if cidr == "" {
				continue
			}
			cfg := map[string]any{
				"transit_gateway_route_table_id": rtID,
				"destination_cidr_block":         cidr,
			}
			if route.State == ec2types.TransitGatewayRouteStateBlackhole {
				cfg["blackhole"] = true
			} else if len(route.TransitGatewayAttachments) > 0 {
				cfg["transit_gateway_attachment_id"] = aws.ToString(route.TransitGatewayAttachments[0].TransitGatewayAttachmentId)
			}
			kids = append(kids, model.Resource{
				Service: "ec2", Type: "transit-gateway-route", TFType: "aws_ec2_transit_gateway_route",
				Region: parent.Region, Account: parent.Account,
				ID: rtID + "_" + cidr, ImportID: rtID + "_" + cidr,
				Config: cfg,
			})
		}
		if out.NextToken == nil || aws.ToString(out.NextToken) == "" {
			break
		}
		routeToken = out.NextToken
	}

	var assocToken *string
	for {
		out, err := cl.GetTransitGatewayRouteTableAssociations(ctx, &ec2.GetTransitGatewayRouteTableAssociationsInput{
			TransitGatewayRouteTableId: &rtID, NextToken: assocToken,
		})
		if err != nil {
			return kids, err
		}
		for _, a := range out.Associations {
			attID := aws.ToString(a.TransitGatewayAttachmentId)
			if attID == "" {
				continue
			}
			kids = append(kids, model.Resource{
				Service: "ec2", Type: "transit-gateway-route-table-association", TFType: "aws_ec2_transit_gateway_route_table_association",
				Region: parent.Region, Account: parent.Account,
				ID: rtID + "_" + attID, ImportID: rtID + "_" + attID,
				Config: map[string]any{
					"transit_gateway_route_table_id": rtID,
					"transit_gateway_attachment_id":  attID,
				},
			})
		}
		if out.NextToken == nil || aws.ToString(out.NextToken) == "" {
			break
		}
		assocToken = out.NextToken
	}

	var propToken *string
	for {
		out, err := cl.GetTransitGatewayRouteTablePropagations(ctx, &ec2.GetTransitGatewayRouteTablePropagationsInput{
			TransitGatewayRouteTableId: &rtID, NextToken: propToken,
		})
		if err != nil {
			return kids, err
		}
		for _, p := range out.TransitGatewayRouteTablePropagations {
			attID := aws.ToString(p.TransitGatewayAttachmentId)
			if attID == "" {
				continue
			}
			kids = append(kids, model.Resource{
				Service: "ec2", Type: "transit-gateway-route-table-propagation", TFType: "aws_ec2_transit_gateway_route_table_propagation",
				Region: parent.Region, Account: parent.Account,
				ID: rtID + "_" + attID, ImportID: rtID + "_" + attID,
				Config: map[string]any{
					"transit_gateway_route_table_id": rtID,
					"transit_gateway_attachment_id":  attID,
				},
			})
		}
		if out.NextToken == nil || aws.ToString(out.NextToken) == "" {
			break
		}
		propToken = out.NextToken
	}

	return kids, nil
}
