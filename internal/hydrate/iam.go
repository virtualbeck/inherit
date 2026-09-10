package hydrate

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/accessanalyzer"
	aatypes "github.com/aws/aws-sdk-go-v2/service/accessanalyzer/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/virtualbeck/inherit-core/model"
)

func init() {
	register("aws_iam_role", hydrateIAMRole)
	register("aws_iam_policy", hydrateIAMPolicy)
	register("aws_iam_user", genericHydratorOverride("aws_iam_user", iamUser, map[string]string{"user_name": "name"}))
	register("aws_iam_group", genericHydratorOverride("aws_iam_group", iamGroup, map[string]string{"group_name": "name"}))
	register("aws_iam_instance_profile", hydrateInstanceProfile)
	register("aws_iam_openid_connect_provider", hydrateOIDCProvider)
	register("aws_iam_saml_provider", hydrateSAMLProvider)
	register("aws_accessanalyzer_analyzer", hydrateAccessAnalyzer)
}

func hydrateIAMRole(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	sch, err := schemaFor("aws_iam_role")
	if err != nil {
		return nil, err
	}
	name := r.ID
	if i := lastSlash(name); i >= 0 {
		name = name[i+1:] // ARN id can be "path/to/RoleName"
	}
	out, err := iam.NewFromConfig(c.Cfg("")).GetRole(ctx, &iam.GetRoleInput{RoleName: &name})
	if err != nil {
		return nil, err
	}
	role := out.Role
	cfg, err := Generic(role, sch, map[string]string{"role_name": "name"})
	if err != nil {
		return nil, err
	}
	if doc := aws.ToString(role.AssumeRolePolicyDocument); doc != "" {
		cfg["assume_role_policy"] = doc // fallback: still valid JSON if somehow already unescaped
		if dec, err := url.QueryUnescape(doc); err == nil {
			cfg["assume_role_policy"] = dec
		}
	}
	delete(cfg, "assume_role_policy_document")
	return cfg, nil
}

func hydrateIAMPolicy(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	sch, err := schemaFor("aws_iam_policy")
	if err != nil {
		return nil, err
	}
	cl := iam.NewFromConfig(c.Cfg(""))
	pol, err := cl.GetPolicy(ctx, &iam.GetPolicyInput{PolicyArn: &r.ARN})
	if err != nil {
		return nil, err
	}
	cfg, err := Generic(pol.Policy, sch, map[string]string{"policy_name": "name"})
	if err != nil {
		return nil, err
	}
	if v := aws.ToString(pol.Policy.DefaultVersionId); v != "" {
		pv, err := cl.GetPolicyVersion(ctx, &iam.GetPolicyVersionInput{PolicyArn: &r.ARN, VersionId: &v})
		if err != nil {
			return nil, err
		}
		if doc := aws.ToString(pv.PolicyVersion.Document); doc != "" {
			cfg["policy"] = doc // fallback: still valid JSON if somehow already unescaped
			if dec, err := url.QueryUnescape(doc); err == nil {
				cfg["policy"] = dec
			}
		}
	}
	if cfg["policy"] == nil {
		return nil, fmt.Errorf("no policy document")
	}
	return cfg, nil
}

func iamUser(ctx context.Context, c *Clients, r model.Resource) (any, error) {
	name := r.ID
	if i := lastSlash(name); i >= 0 {
		name = name[i+1:]
	}
	out, err := iam.NewFromConfig(c.Cfg("")).GetUser(ctx, &iam.GetUserInput{UserName: &name})
	if err != nil {
		return nil, err
	}
	return out.User, nil
}

func iamGroup(ctx context.Context, c *Clients, r model.Resource) (any, error) {
	name := r.ID
	if i := lastSlash(name); i >= 0 {
		name = name[i+1:]
	}
	out, err := iam.NewFromConfig(c.Cfg("")).GetGroup(ctx, &iam.GetGroupInput{GroupName: &name})
	if err != nil {
		return nil, err
	}
	return out.Group, nil
}

func hydrateInstanceProfile(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	name := r.ID
	if i := lastSlash(name); i >= 0 {
		name = name[i+1:]
	}
	out, err := iam.NewFromConfig(c.Cfg("")).GetInstanceProfile(ctx, &iam.GetInstanceProfileInput{InstanceProfileName: &name})
	if err != nil {
		return nil, err
	}
	p := out.InstanceProfile
	cfg := map[string]any{"name": aws.ToString(p.InstanceProfileName), "path": aws.ToString(p.Path)}
	if len(p.Roles) > 0 {
		cfg["role"] = aws.ToString(p.Roles[0].RoleName)
	}
	return cfg, nil
}

func hydrateOIDCProvider(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	out, err := iam.NewFromConfig(c.Cfg("")).GetOpenIDConnectProvider(ctx, &iam.GetOpenIDConnectProviderInput{OpenIDConnectProviderArn: &r.ARN})
	if err != nil {
		return nil, err
	}
	cfg := map[string]any{"url": "https://" + aws.ToString(out.Url)}
	if len(out.ClientIDList) > 0 {
		cfg["client_id_list"] = toAny(out.ClientIDList)
	}
	if len(out.ThumbprintList) > 0 {
		cfg["thumbprint_list"] = toAny(out.ThumbprintList)
	}
	return cfg, nil
}

func hydrateSAMLProvider(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	out, err := iam.NewFromConfig(c.Cfg("")).GetSAMLProvider(ctx, &iam.GetSAMLProviderInput{SAMLProviderArn: &r.ARN})
	if err != nil {
		return nil, err
	}
	name := r.ID
	if i := lastSlash(name); i >= 0 {
		name = name[i+1:]
	}
	cfg := map[string]any{"name": name}
	if d := aws.ToString(out.SAMLMetadataDocument); d != "" {
		cfg["saml_metadata_document"] = d
	}
	return cfg, nil
}

func hydrateAccessAnalyzer(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	name := r.ID
	if _, rest, ok := strings.Cut(r.ID, "/"); ok {
		name = rest
	}
	out, err := accessanalyzer.NewFromConfig(c.Cfg(r.Region)).GetAnalyzer(ctx, &accessanalyzer.GetAnalyzerInput{AnalyzerName: &name})
	if err != nil {
		return nil, err
	}
	if out.Analyzer == nil {
		return nil, fmt.Errorf("not found")
	}
	cfg := map[string]any{
		"analyzer_name": aws.ToString(out.Analyzer.Name),
		"type":          string(out.Analyzer.Type),
	}
	switch conf := out.Analyzer.Configuration.(type) {
	case *aatypes.AnalyzerConfigurationMemberUnusedAccess:
		ua := map[string]any{}
		if conf.Value.UnusedAccessAge != nil {
			ua["unused_access_age"] = *conf.Value.UnusedAccessAge
		}
		if ar := conf.Value.AnalysisRule; ar != nil && len(ar.Exclusions) > 0 {
			var exclusions []any
			for _, e := range ar.Exclusions {
				m := map[string]any{}
				if len(e.AccountIds) > 0 {
					m["account_ids"] = toAny(e.AccountIds)
				}
				if len(e.ResourceTags) > 0 {
					var tags []any
					for _, t := range e.ResourceTags {
						tm := make(map[string]any, len(t))
						for k, v := range t {
							tm[k] = v
						}
						tags = append(tags, tm)
					}
					m["resource_tags"] = tags
				}
				exclusions = append(exclusions, m)
			}
			ua["analysis_rule"] = []any{map[string]any{"exclusion": exclusions}}
		}
		cfg["configuration"] = []any{map[string]any{"unused_access": []any{ua}}}
	case *aatypes.AnalyzerConfigurationMemberInternalAccess:
		ia := map[string]any{}
		if ar := conf.Value.AnalysisRule; ar != nil && len(ar.Inclusions) > 0 {
			var inclusions []any
			for _, in := range ar.Inclusions {
				m := map[string]any{}
				if len(in.AccountIds) > 0 {
					m["account_ids"] = toAny(in.AccountIds)
				}
				if len(in.ResourceArns) > 0 {
					m["resource_arns"] = toAny(in.ResourceArns)
				}
				if len(in.ResourceTypes) > 0 {
					var rts []any
					for _, t := range in.ResourceTypes {
						rts = append(rts, string(t))
					}
					m["resource_types"] = rts
				}
				inclusions = append(inclusions, m)
			}
			ia["analysis_rule"] = []any{map[string]any{"inclusion": inclusions}}
		}
		cfg["configuration"] = []any{map[string]any{"internal_access": []any{ia}}}
	}
	return cfg, nil
}
