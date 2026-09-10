package hydrate

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudfront"
	cftypes "github.com/aws/aws-sdk-go-v2/service/cloudfront/types"
	"github.com/aws/aws-sdk-go-v2/service/globalaccelerator"
	"github.com/aws/aws-sdk-go-v2/service/wafv2"
	wafv2types "github.com/aws/aws-sdk-go-v2/service/wafv2/types"
	"github.com/virtualbeck/inherit-core/model"
)

func init() {
	register("aws_cloudfront_distribution", hydrateCloudFront)
	register("aws_cloudfront_vpc_origin", hydrateCloudFrontVpcOrigin)
	register("aws_globalaccelerator_accelerator", hydrateGAAccelerator)
	register("aws_wafv2_ip_set", hydrateWAFIPSet)
	register("aws_wafv2_regex_pattern_set", hydrateWAFRegexSet)
}

// vpc_origin_endpoint_config is a Required block (the provider rejects the
// resource outright without one) -- built explicitly rather than through
// Generic(), whose nested-block handling treats a block as valid only if
// every one of its Required sub-attributes survived pruning, dropping the
// entire block otherwise with nothing to say why. Building it directly
// guarantees the block a Required block needs is always present.
func hydrateCloudFrontVpcOrigin(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	out, err := cloudfront.NewFromConfig(c.Cfg("us-east-1")).GetVpcOrigin(ctx, &cloudfront.GetVpcOriginInput{Id: &r.ID})
	if err != nil {
		return nil, err
	}
	if out.VpcOrigin == nil || out.VpcOrigin.VpcOriginEndpointConfig == nil {
		return nil, fmt.Errorf("no vpc origin endpoint config returned for %s", r.ID)
	}
	ec := out.VpcOrigin.VpcOriginEndpointConfig
	endpointCfg := map[string]any{
		"arn":                    aws.ToString(ec.Arn),
		"http_port":              aws.ToInt32(ec.HTTPPort),
		"https_port":             aws.ToInt32(ec.HTTPSPort),
		"name":                   aws.ToString(ec.Name),
		"origin_protocol_policy": string(ec.OriginProtocolPolicy),
	}
	if p := ec.OriginSslProtocols; p != nil && len(p.Items) > 0 {
		items := make([]any, len(p.Items))
		for i, it := range p.Items {
			items[i] = string(it)
		}
		endpointCfg["origin_ssl_protocols"] = map[string]any{
			"items":    items,
			"quantity": aws.ToInt32(p.Quantity),
		}
	}
	return map[string]any{"vpc_origin_endpoint_config": endpointCfg}, nil
}

// aws_cloudfront_distribution is one large resource with several required nested
// blocks (origin, default_cache_behavior, restrictions, viewer_certificate).
// GetDistribution returns all of it in DistributionConfig.
func hydrateCloudFront(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	out, err := cloudfront.NewFromConfig(c.Cfg("us-east-1")).GetDistribution(ctx, &cloudfront.GetDistributionInput{Id: &r.ID})
	if err != nil {
		return nil, err
	}
	d := out.Distribution.DistributionConfig

	cfg := map[string]any{
		"enabled":         aws.ToBool(d.Enabled),
		"is_ipv6_enabled": aws.ToBool(d.IsIPV6Enabled),
	}
	if v := aws.ToString(d.Comment); v != "" {
		cfg["comment"] = v
	}
	if v := aws.ToString(d.DefaultRootObject); v != "" {
		cfg["default_root_object"] = v
	}
	if v := string(d.PriceClass); v != "" {
		cfg["price_class"] = v
	}
	if v := string(d.HttpVersion); v != "" {
		cfg["http_version"] = v
	}
	if v := aws.ToString(d.WebACLId); v != "" {
		cfg["web_acl_id"] = v
	}
	if d.Aliases != nil && len(d.Aliases.Items) > 0 {
		cfg["aliases"] = toAny(d.Aliases.Items)
	}

	if d.Origins != nil {
		var origins []any
		for _, o := range d.Origins.Items {
			origins = append(origins, cfOrigin(o))
		}
		if len(origins) > 0 {
			cfg["origin"] = origins
		}
	}

	cfg["default_cache_behavior"] = cfBehavior(cftypes.CacheBehavior{
		TargetOriginId:             d.DefaultCacheBehavior.TargetOriginId,
		ViewerProtocolPolicy:       d.DefaultCacheBehavior.ViewerProtocolPolicy,
		AllowedMethods:             d.DefaultCacheBehavior.AllowedMethods,
		Compress:                   d.DefaultCacheBehavior.Compress,
		CachePolicyId:              d.DefaultCacheBehavior.CachePolicyId,
		OriginRequestPolicyId:      d.DefaultCacheBehavior.OriginRequestPolicyId,
		ResponseHeadersPolicyId:    d.DefaultCacheBehavior.ResponseHeadersPolicyId,
		MinTTL:                     d.DefaultCacheBehavior.MinTTL,
		DefaultTTL:                 d.DefaultCacheBehavior.DefaultTTL,
		MaxTTL:                     d.DefaultCacheBehavior.MaxTTL,
		SmoothStreaming:            d.DefaultCacheBehavior.SmoothStreaming,
		FieldLevelEncryptionId:     d.DefaultCacheBehavior.FieldLevelEncryptionId,
		ForwardedValues:            d.DefaultCacheBehavior.ForwardedValues,
		LambdaFunctionAssociations: d.DefaultCacheBehavior.LambdaFunctionAssociations,
		FunctionAssociations:       d.DefaultCacheBehavior.FunctionAssociations,
		TrustedKeyGroups:           d.DefaultCacheBehavior.TrustedKeyGroups,
	})

	if d.CacheBehaviors != nil && len(d.CacheBehaviors.Items) > 0 {
		var obs []any
		for _, b := range d.CacheBehaviors.Items {
			m := cfBehavior(b)
			m["path_pattern"] = aws.ToString(b.PathPattern)
			obs = append(obs, m)
		}
		cfg["ordered_cache_behavior"] = obs
	}

	if d.CustomErrorResponses != nil {
		var errs []any
		for _, e := range d.CustomErrorResponses.Items {
			m := map[string]any{"error_code": aws.ToInt32(e.ErrorCode)}
			if e.ResponseCode != nil && aws.ToString(e.ResponseCode) != "" {
				m["response_code"] = aws.ToString(e.ResponseCode)
			}
			if v := aws.ToString(e.ResponsePagePath); v != "" {
				m["response_page_path"] = v
			}
			if e.ErrorCachingMinTTL != nil {
				m["error_caching_min_ttl"] = *e.ErrorCachingMinTTL
			}
			errs = append(errs, m)
		}
		if len(errs) > 0 {
			cfg["custom_error_response"] = errs
		}
	}

	geo := map[string]any{"restriction_type": "none"}
	if d.Restrictions != nil && d.Restrictions.GeoRestriction != nil {
		geo["restriction_type"] = string(d.Restrictions.GeoRestriction.RestrictionType)
		if len(d.Restrictions.GeoRestriction.Items) > 0 {
			geo["locations"] = toAny(d.Restrictions.GeoRestriction.Items)
		}
	}
	cfg["restrictions"] = map[string]any{"geo_restriction": geo}

	vc := map[string]any{}
	if d.ViewerCertificate != nil {
		v := d.ViewerCertificate
		switch {
		case aws.ToString(v.ACMCertificateArn) != "":
			vc["acm_certificate_arn"] = aws.ToString(v.ACMCertificateArn)
		case aws.ToString(v.IAMCertificateId) != "":
			vc["iam_certificate_id"] = aws.ToString(v.IAMCertificateId)
		default:
			vc["cloudfront_default_certificate"] = true
		}
		if s := string(v.MinimumProtocolVersion); s != "" {
			vc["minimum_protocol_version"] = s
		}
		if s := string(v.SSLSupportMethod); s != "" {
			vc["ssl_support_method"] = s
		}
	} else {
		vc["cloudfront_default_certificate"] = true
	}
	cfg["viewer_certificate"] = vc

	if d.Logging != nil && aws.ToBool(d.Logging.Enabled) {
		lc := map[string]any{"bucket": aws.ToString(d.Logging.Bucket)}
		if v := aws.ToString(d.Logging.Prefix); v != "" {
			lc["prefix"] = v
		}
		lc["include_cookies"] = aws.ToBool(d.Logging.IncludeCookies)
		cfg["logging_config"] = lc
	}

	return cfg, nil
}

func cfOrigin(o cftypes.Origin) map[string]any {
	m := map[string]any{
		"origin_id":   aws.ToString(o.Id),
		"domain_name": aws.ToString(o.DomainName),
	}
	if v := aws.ToString(o.OriginPath); v != "" {
		m["origin_path"] = v
	}
	if o.ConnectionAttempts != nil {
		m["connection_attempts"] = *o.ConnectionAttempts
	}
	if o.ConnectionTimeout != nil {
		m["connection_timeout"] = *o.ConnectionTimeout
	}
	if v := aws.ToString(o.OriginAccessControlId); v != "" {
		m["origin_access_control_id"] = v
	}
	if o.CustomHeaders != nil {
		var hs []any
		for _, h := range o.CustomHeaders.Items {
			hs = append(hs, map[string]any{"name": aws.ToString(h.HeaderName), "value": aws.ToString(h.HeaderValue)})
		}
		if len(hs) > 0 {
			m["custom_header"] = hs
		}
	}
	switch {
	case o.CustomOriginConfig != nil:
		// handled below
	case aws.ToString(o.OriginAccessControlId) != "":
		// OAC origins: no s3_origin_config block
	case o.S3OriginConfig != nil:
		m["s3_origin_config"] = map[string]any{"origin_access_identity": aws.ToString(o.S3OriginConfig.OriginAccessIdentity)}
	}
	if o.CustomOriginConfig != nil {
		co := o.CustomOriginConfig
		cm := map[string]any{
			"http_port":              aws.ToInt32(co.HTTPPort),
			"https_port":             aws.ToInt32(co.HTTPSPort),
			"origin_protocol_policy": string(co.OriginProtocolPolicy),
		}
		if co.OriginSslProtocols != nil {
			var ps []any
			for _, p := range co.OriginSslProtocols.Items {
				ps = append(ps, string(p))
			}
			cm["origin_ssl_protocols"] = ps
		}
		if co.OriginReadTimeout != nil {
			cm["origin_read_timeout"] = *co.OriginReadTimeout
		}
		if co.OriginKeepaliveTimeout != nil {
			cm["origin_keepalive_timeout"] = *co.OriginKeepaliveTimeout
		}
		m["custom_origin_config"] = cm
	}
	if vo := o.VpcOriginConfig; vo != nil {
		vm := map[string]any{"vpc_origin_id": aws.ToString(vo.VpcOriginId)}
		if vo.OriginReadTimeout != nil {
			vm["origin_read_timeout"] = *vo.OriginReadTimeout
		}
		if vo.OriginKeepaliveTimeout != nil {
			vm["origin_keepalive_timeout"] = *vo.OriginKeepaliveTimeout
		}
		m["vpc_origin_config"] = vm
	}
	return m
}

func cfBehavior(b cftypes.CacheBehavior) map[string]any {
	m := map[string]any{
		"target_origin_id":       aws.ToString(b.TargetOriginId),
		"viewer_protocol_policy": string(b.ViewerProtocolPolicy),
	}
	if b.AllowedMethods != nil {
		var am, cm []any
		for _, x := range b.AllowedMethods.Items {
			am = append(am, string(x))
		}
		m["allowed_methods"] = am
		if b.AllowedMethods.CachedMethods != nil {
			for _, x := range b.AllowedMethods.CachedMethods.Items {
				cm = append(cm, string(x))
			}
			m["cached_methods"] = cm
		}
	}
	if b.Compress != nil {
		m["compress"] = *b.Compress
	}
	if v := aws.ToString(b.CachePolicyId); v != "" {
		m["cache_policy_id"] = v
	}
	if v := aws.ToString(b.OriginRequestPolicyId); v != "" {
		m["origin_request_policy_id"] = v
	}
	if v := aws.ToString(b.ResponseHeadersPolicyId); v != "" {
		m["response_headers_policy_id"] = v
	}
	if v := aws.ToString(b.FieldLevelEncryptionId); v != "" {
		m["field_level_encryption_id"] = v
	}
	if b.SmoothStreaming != nil {
		m["smooth_streaming"] = *b.SmoothStreaming
	}
	if b.MinTTL != nil {
		m["min_ttl"] = *b.MinTTL
	}
	if b.DefaultTTL != nil {
		m["default_ttl"] = *b.DefaultTTL
	}
	if b.MaxTTL != nil {
		m["max_ttl"] = *b.MaxTTL
	}
	if b.TrustedKeyGroups != nil && len(b.TrustedKeyGroups.Items) > 0 {
		m["trusted_key_groups"] = toAny(b.TrustedKeyGroups.Items)
	}
	// the provider requires exactly one of cache_policy_id or forwarded_values
	if aws.ToString(b.CachePolicyId) == "" {
		fv := map[string]any{"query_string": false, "cookies": map[string]any{"forward": "none"}}
		if b.ForwardedValues != nil {
			fv["query_string"] = aws.ToBool(b.ForwardedValues.QueryString)
			if b.ForwardedValues.Cookies != nil {
				ck := map[string]any{"forward": string(b.ForwardedValues.Cookies.Forward)}
				if b.ForwardedValues.Cookies.WhitelistedNames != nil && len(b.ForwardedValues.Cookies.WhitelistedNames.Items) > 0 {
					ck["whitelisted_names"] = toAny(b.ForwardedValues.Cookies.WhitelistedNames.Items)
				}
				fv["cookies"] = ck
			}
			if b.ForwardedValues.Headers != nil && len(b.ForwardedValues.Headers.Items) > 0 {
				fv["headers"] = toAny(b.ForwardedValues.Headers.Items)
			}
			if b.ForwardedValues.QueryStringCacheKeys != nil && len(b.ForwardedValues.QueryStringCacheKeys.Items) > 0 {
				fv["query_string_cache_keys"] = toAny(b.ForwardedValues.QueryStringCacheKeys.Items)
			}
		}
		m["forwarded_values"] = fv
	}
	for _, la := range cfLambdaAssoc(b.LambdaFunctionAssociations) {
		appendAny(m, "lambda_function_association", la)
	}
	for _, fa := range cfFuncAssoc(b.FunctionAssociations) {
		appendAny(m, "function_association", fa)
	}
	return m
}

func cfLambdaAssoc(a *cftypes.LambdaFunctionAssociations) []any {
	if a == nil {
		return nil
	}
	var out []any
	for _, x := range a.Items {
		m := map[string]any{
			"event_type": string(x.EventType),
			"lambda_arn": aws.ToString(x.LambdaFunctionARN),
		}
		if x.IncludeBody != nil {
			m["include_body"] = *x.IncludeBody
		}
		out = append(out, m)
	}
	return out
}

func cfFuncAssoc(a *cftypes.FunctionAssociations) []any {
	if a == nil {
		return nil
	}
	var out []any
	for _, x := range a.Items {
		out = append(out, map[string]any{
			"event_type":   string(x.EventType),
			"function_arn": aws.ToString(x.FunctionARN),
		})
	}
	return out
}

func appendAny(m map[string]any, key string, v any) {
	existing, _ := m[key].([]any)
	m[key] = append(existing, v)
}

func hydrateGAAccelerator(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	// Global Accelerator is a global service fronted from us-west-2.
	arn := r.ARN
	out, err := globalaccelerator.NewFromConfig(c.Cfg("us-west-2")).DescribeAccelerator(ctx, &globalaccelerator.DescribeAcceleratorInput{AcceleratorArn: &arn})
	if err != nil {
		return nil, err
	}
	a := out.Accelerator
	cfg := map[string]any{
		"name": aws.ToString(a.Name),
	}
	if v := string(a.IpAddressType); v != "" {
		cfg["ip_address_type"] = v
	}
	if a.Enabled != nil {
		cfg["enabled"] = *a.Enabled
	}
	return cfg, nil
}

func hydrateWAFIPSet(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	id, name, scope := parseWAFArn(r)
	out, err := wafv2.NewFromConfig(c.Cfg(r.Region)).GetIPSet(ctx, &wafv2.GetIPSetInput{Id: &id, Name: &name, Scope: scope})
	if err != nil {
		return nil, err
	}
	s := out.IPSet
	cfg := map[string]any{
		"name":               aws.ToString(s.Name),
		"scope":              string(scope),
		"ip_address_version": string(s.IPAddressVersion),
		"addresses":          toAny(s.Addresses),
	}
	if v := aws.ToString(s.Description); v != "" {
		cfg["description"] = v
	}
	return cfg, nil
}

func hydrateWAFRegexSet(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	id, name, scope := parseWAFArn(r)
	out, err := wafv2.NewFromConfig(c.Cfg(r.Region)).GetRegexPatternSet(ctx, &wafv2.GetRegexPatternSetInput{Id: &id, Name: &name, Scope: scope})
	if err != nil {
		return nil, err
	}
	s := out.RegexPatternSet
	cfg := map[string]any{
		"name":  aws.ToString(s.Name),
		"scope": string(scope),
	}
	if v := aws.ToString(s.Description); v != "" {
		cfg["description"] = v
	}
	var pats []any
	for _, p := range s.RegularExpressionList {
		pats = append(pats, map[string]any{"regex_string": aws.ToString(p.RegexString)})
	}
	if len(pats) > 0 {
		cfg["regular_expression"] = pats
	}
	return cfg, nil
}

// parseWAFArn pulls the id, name and scope out of a discovered wafv2 resource.
// The ARN resource segment is "<scope>/<kind>/<name>/<id>", so r.Type holds the
// scope word and r.ID holds "<kind>/<name>/<id>".
func parseWAFArn(r model.Resource) (id, name string, scope wafv2types.Scope) {
	scope = wafv2types.ScopeRegional
	if r.Type == "global" {
		scope = wafv2types.ScopeCloudfront
	}
	parts := strings.Split(r.ID, "/")
	if len(parts) >= 3 {
		name = parts[len(parts)-2]
		id = parts[len(parts)-1]
	}
	return id, name, scope
}
