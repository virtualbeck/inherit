package hydrate

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/virtualbeck/inherit/model"
)

// Generic() for most; authentication_options is hand-flattened.
func init() { register("aws_ec2_client_vpn_endpoint", hydrateClientVPNEndpoint) }

func hydrateClientVPNEndpoint(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	id := r.ID
	out, err := ec2.NewFromConfig(c.Cfg(r.Region)).DescribeClientVpnEndpoints(ctx, &ec2.DescribeClientVpnEndpointsInput{ClientVpnEndpointIds: []string{id}})
	if err != nil {
		return nil, err
	}
	if len(out.ClientVpnEndpoints) == 0 {
		return nil, nil
	}
	e := out.ClientVpnEndpoints[0]
	sch, err := schemaFor("aws_ec2_client_vpn_endpoint")
	if err != nil {
		return nil, err
	}
	cfg, err := Generic(e, sch, nil)
	if err != nil {
		return nil, err
	}
	if len(e.AuthenticationOptions) > 0 {
		var opts []any
		for _, a := range e.AuthenticationOptions {
			o := map[string]any{"type": string(a.Type)}
			if a.ActiveDirectory != nil {
				o["active_directory_id"] = aws.ToString(a.ActiveDirectory.DirectoryId)
			}
			if a.MutualAuthentication != nil {
				o["root_certificate_chain_arn"] = aws.ToString(a.MutualAuthentication.ClientRootCertificateChain)
			}
			if a.FederatedAuthentication != nil {
				if v := aws.ToString(a.FederatedAuthentication.SamlProviderArn); v != "" {
					o["saml_provider_arn"] = v
				}
				if v := aws.ToString(a.FederatedAuthentication.SelfServiceSamlProviderArn); v != "" {
					o["self_service_saml_provider_arn"] = v
				}
			}
			opts = append(opts, o)
		}
		cfg["authentication_options"] = opts
	}
	return cfg, nil
}
