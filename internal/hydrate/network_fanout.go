package hydrate

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/virtualbeck/inherit-core/model"
)

func init() {
	registerFanout("aws_route_table", fanoutRouteTableAssoc)
}

// fanoutRouteTableAssoc emits an aws_route_table_association per explicit
// subnet / gateway association of a route table.
func fanoutRouteTableAssoc(ctx context.Context, c *Clients, parent model.Resource) ([]model.Resource, error) {
	out, err := ec2.NewFromConfig(c.Cfg(parent.Region)).DescribeRouteTables(ctx, &ec2.DescribeRouteTablesInput{
		RouteTableIds: []string{parent.ID},
	})
	if err != nil || len(out.RouteTables) == 0 {
		return nil, err
	}
	var kids []model.Resource
	for _, a := range out.RouteTables[0].Associations {
		if aws.ToBool(a.Main) {
			continue // the implicit main association is not importable
		}
		cfg := map[string]any{"route_table_id": parent.ID}
		var importID string
		switch {
		case aws.ToString(a.SubnetId) != "":
			cfg["subnet_id"] = aws.ToString(a.SubnetId)
			importID = aws.ToString(a.SubnetId) + "/" + parent.ID
		case aws.ToString(a.GatewayId) != "":
			cfg["gateway_id"] = aws.ToString(a.GatewayId)
			importID = aws.ToString(a.GatewayId) + "/" + parent.ID
		default:
			continue
		}
		kids = append(kids, model.Resource{
			Service: "ec2", Type: "route-table-association", TFType: "aws_route_table_association",
			Region: parent.Region, Account: parent.Account,
			ID:       aws.ToString(a.RouteTableAssociationId),
			ImportID: importID,
			Config:   cfg,
		})
	}
	return kids, nil
}
