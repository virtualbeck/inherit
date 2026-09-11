package hydrate

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudfront"
	cftypes "github.com/aws/aws-sdk-go-v2/service/cloudfront/types"
	"github.com/virtualbeck/inherit/model"
)

func init() {
	registerGlobalGapFiller(gapFillCloudFrontExtras)
	register("aws_cloudfront_function", hydrateCloudFrontFunction)
}

// gapFillCloudFrontExtras discovers the CloudFront primitives that have no
// ARN/tagging concept at all in this schema version (origin access
// controls/identities, cache/origin-request/response-headers policies,
// public keys, key groups) -- account-wide, global-service lists.
// aws_cloudfront_function is the one type here that IS ARN-taggable
// (arn:aws:cloudfront::account:function/name), so it's registered normally
// via arnToTF/register() below instead of gap-filled.
func gapFillCloudFrontExtras(ctx context.Context, c *Clients, _ string) ([]model.Resource, error) {
	cl := cloudfront.NewFromConfig(c.Cfg("us-east-1"))
	var out []model.Resource

	if oacs, err := cl.ListOriginAccessControls(ctx, &cloudfront.ListOriginAccessControlsInput{}); err == nil && oacs.OriginAccessControlList != nil {
		for _, s := range oacs.OriginAccessControlList.Items {
			id := aws.ToString(s.Id)
			out = append(out, model.Resource{
				Service: "cloudfront", Type: "origin-access-control", TFType: "aws_cloudfront_origin_access_control",
				ID: id, ImportID: id,
				Config: map[string]any{
					"name":                              aws.ToString(s.Name),
					"origin_access_control_origin_type": string(s.OriginAccessControlOriginType),
					"signing_behavior":                  string(s.SigningBehavior),
					"signing_protocol":                  string(s.SigningProtocol),
					"description":                       aws.ToString(s.Description),
				},
			})
		}
	}

	if oais, err := cl.ListCloudFrontOriginAccessIdentities(ctx, &cloudfront.ListCloudFrontOriginAccessIdentitiesInput{}); err == nil && oais.CloudFrontOriginAccessIdentityList != nil {
		for _, s := range oais.CloudFrontOriginAccessIdentityList.Items {
			id := aws.ToString(s.Id)
			cfg := map[string]any{}
			if v := aws.ToString(s.Comment); v != "" {
				cfg["comment"] = v
			}
			out = append(out, model.Resource{
				Service: "cloudfront", Type: "origin-access-identity", TFType: "aws_cloudfront_origin_access_identity",
				ID: id, ImportID: id,
				Config: cfg,
			})
		}
	}

	sch, _ := schemaFor("aws_cloudfront_cache_policy")
	if cps, err := cl.ListCachePolicies(ctx, &cloudfront.ListCachePoliciesInput{Type: cftypes.CachePolicyTypeCustom}); err == nil && cps.CachePolicyList != nil {
		for _, s := range cps.CachePolicyList.Items {
			if s.CachePolicy == nil || s.CachePolicy.CachePolicyConfig == nil {
				continue
			}
			id := aws.ToString(s.CachePolicy.Id)
			cfg, _ := Generic(s.CachePolicy.CachePolicyConfig, sch, nil)
			if cfg == nil {
				continue
			}
			out = append(out, model.Resource{
				Service: "cloudfront", Type: "cache-policy", TFType: "aws_cloudfront_cache_policy",
				ID: id, ImportID: id,
				Config: cfg,
			})
		}
	}

	orpSch, _ := schemaFor("aws_cloudfront_origin_request_policy")
	if orps, err := cl.ListOriginRequestPolicies(ctx, &cloudfront.ListOriginRequestPoliciesInput{Type: cftypes.OriginRequestPolicyTypeCustom}); err == nil && orps.OriginRequestPolicyList != nil {
		for _, s := range orps.OriginRequestPolicyList.Items {
			if s.OriginRequestPolicy == nil || s.OriginRequestPolicy.OriginRequestPolicyConfig == nil {
				continue
			}
			id := aws.ToString(s.OriginRequestPolicy.Id)
			cfg, _ := Generic(s.OriginRequestPolicy.OriginRequestPolicyConfig, orpSch, nil)
			if cfg == nil {
				continue
			}
			out = append(out, model.Resource{
				Service: "cloudfront", Type: "origin-request-policy", TFType: "aws_cloudfront_origin_request_policy",
				ID: id, ImportID: id,
				Config: cfg,
			})
		}
	}

	rhpSch, _ := schemaFor("aws_cloudfront_response_headers_policy")
	if rhps, err := cl.ListResponseHeadersPolicies(ctx, &cloudfront.ListResponseHeadersPoliciesInput{Type: cftypes.ResponseHeadersPolicyTypeCustom}); err == nil && rhps.ResponseHeadersPolicyList != nil {
		for _, s := range rhps.ResponseHeadersPolicyList.Items {
			if s.ResponseHeadersPolicy == nil || s.ResponseHeadersPolicy.ResponseHeadersPolicyConfig == nil {
				continue
			}
			id := aws.ToString(s.ResponseHeadersPolicy.Id)
			cfg, _ := Generic(s.ResponseHeadersPolicy.ResponseHeadersPolicyConfig, rhpSch, nil)
			if cfg == nil {
				continue
			}
			out = append(out, model.Resource{
				Service: "cloudfront", Type: "response-headers-policy", TFType: "aws_cloudfront_response_headers_policy",
				ID: id, ImportID: id,
				Config: cfg,
			})
		}
	}

	if pks, err := cl.ListPublicKeys(ctx, &cloudfront.ListPublicKeysInput{}); err == nil && pks.PublicKeyList != nil {
		for _, s := range pks.PublicKeyList.Items {
			id := aws.ToString(s.Id)
			cfg := map[string]any{
				"name":        aws.ToString(s.Name),
				"encoded_key": aws.ToString(s.EncodedKey),
			}
			if v := aws.ToString(s.Comment); v != "" {
				cfg["comment"] = v
			}
			out = append(out, model.Resource{
				Service: "cloudfront", Type: "public-key", TFType: "aws_cloudfront_public_key",
				ID: id, ImportID: id,
				Config: cfg,
			})
		}
	}

	if kgs, err := cl.ListKeyGroups(ctx, &cloudfront.ListKeyGroupsInput{}); err == nil && kgs.KeyGroupList != nil {
		for _, s := range kgs.KeyGroupList.Items {
			if s.KeyGroup == nil || s.KeyGroup.KeyGroupConfig == nil {
				continue
			}
			id := aws.ToString(s.KeyGroup.Id)
			cfg := map[string]any{"name": aws.ToString(s.KeyGroup.KeyGroupConfig.Name)}
			if len(s.KeyGroup.KeyGroupConfig.Items) > 0 {
				cfg["items"] = toAny(s.KeyGroup.KeyGroupConfig.Items)
			}
			if v := aws.ToString(s.KeyGroup.KeyGroupConfig.Comment); v != "" {
				cfg["comment"] = v
			}
			out = append(out, model.Resource{
				Service: "cloudfront", Type: "key-group", TFType: "aws_cloudfront_key_group",
				ID: id, ImportID: id,
				Config: cfg,
			})
		}
	}

	return out, nil
}

func hydrateCloudFrontFunction(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	cl := cloudfront.NewFromConfig(c.Cfg("us-east-1"))
	name := r.ID
	desc, err := cl.DescribeFunction(ctx, &cloudfront.DescribeFunctionInput{Name: &name})
	if err != nil {
		return nil, err
	}
	fs := desc.FunctionSummary
	if fs == nil || fs.FunctionConfig == nil {
		return nil, fmt.Errorf("not found")
	}
	code, err := cl.GetFunction(ctx, &cloudfront.GetFunctionInput{Name: &name})
	if err != nil {
		return nil, err
	}
	cfg := map[string]any{
		"name":    name,
		"runtime": string(fs.FunctionConfig.Runtime),
		"code":    string(code.FunctionCode),
	}
	if v := aws.ToString(fs.FunctionConfig.Comment); v != "" {
		cfg["comment"] = v
	}
	return cfg, nil
}
