package hydrate

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/virtualbeck/inherit/model"
)

func init() {
	registerFanout("aws_lambda_function", fanoutLambda)
	register("aws_lambda_code_signing_config", hydrateLambdaCodeSigningConfig)
}

func hydrateLambdaCodeSigningConfig(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	arn := r.ARN
	out, err := lambda.NewFromConfig(c.Cfg(r.Region)).GetCodeSigningConfig(ctx, &lambda.GetCodeSigningConfigInput{CodeSigningConfigArn: &arn})
	if err != nil {
		return nil, err
	}
	cs := out.CodeSigningConfig
	if cs == nil {
		return nil, fmt.Errorf("not found")
	}
	cfg := map[string]any{}
	if v := aws.ToString(cs.Description); v != "" {
		cfg["description"] = v
	}
	if cs.AllowedPublishers != nil && len(cs.AllowedPublishers.SigningProfileVersionArns) > 0 {
		cfg["allowed_publishers"] = []any{map[string]any{
			"signing_profile_version_arns": toAny(cs.AllowedPublishers.SigningProfileVersionArns),
		}}
	}
	if cs.CodeSigningPolicies != nil {
		cfg["policies"] = []any{map[string]any{
			"untrusted_artifact_on_deployment": string(cs.CodeSigningPolicies.UntrustedArtifactOnDeployment),
		}}
	}
	return cfg, nil
}

// fanoutLambda emits the event-source mappings and aliases of a function as
// their own resources.
func fanoutLambda(ctx context.Context, c *Clients, parent model.Resource) ([]model.Resource, error) {
	cl := lambda.NewFromConfig(c.Cfg(parent.Region))
	fn := parent.ID
	var kids []model.Resource

	if esm, err := cl.ListEventSourceMappings(ctx, &lambda.ListEventSourceMappingsInput{FunctionName: &fn}); err == nil {
		sch, serr := schemaFor("aws_lambda_event_source_mapping")
		for _, m := range esm.EventSourceMappings {
			var cfg map[string]any
			if serr == nil {
				// Generic() over the whole struct instead of a hand-picked
				// subset: this resource has ~20 real, independently
				// configurable attributes (filter_criteria, destination_config
				// for on-failure DLQ routing, scaling/provisioned-poller
				// config, retry/batching tuning, the msk/mq/kafka/documentdb
				// source-specific blocks, ...). function_arn is Computed-only
				// in the schema (function_name is the real Required arg), so
				// it's overridden to land there instead of being pruned away
				// -- GetEventSourceMappingConfiguration never returns a
				// separate bare function name, only the ARN.
				cfg, _ = Generic(m, sch, map[string]string{"function_arn": "function_name"})
			}
			if cfg == nil {
				cfg = map[string]any{
					"function_name":    aws.ToString(m.FunctionArn),
					"event_source_arn": aws.ToString(m.EventSourceArn),
				}
			}
			// state is Computed-only (enabled is the real settable arg) and
			// isn't a simple case-conversion of it -- "Enabled" maps to
			// true, everything else (Disabled, Creating, Updating,
			// transitional states) to false.
			cfg["enabled"] = aws.ToString(m.State) == "Enabled"
			fixSelfManagedEndpoints(cfg)
			// Lambda tags this resource via the generic ARN-keyed ListTags
			// API, same as the function itself -- ListEventSourceMappings/
			// GetEventSourceMappingConfiguration never return tags in the
			// mapping's own response.
			var tags map[string]string
			if esmARN := aws.ToString(m.EventSourceMappingArn); esmARN != "" {
				if lt, err := cl.ListTags(ctx, &lambda.ListTagsInput{Resource: &esmARN}); err == nil && len(lt.Tags) > 0 {
					tags = lt.Tags
					cfg["tags"] = tags
				}
			}
			kids = append(kids, model.Resource{
				Service: "lambda", Type: "event-source-mapping", TFType: "aws_lambda_event_source_mapping",
				Region: parent.Region, Account: parent.Account,
				ID:     aws.ToString(m.UUID),
				Tags:   tags,
				Config: cfg,
			})
		}
	}

	kids = append(kids, fanoutLambdaPermissions(ctx, cl, parent)...)

	if als, err := cl.ListAliases(ctx, &lambda.ListAliasesInput{FunctionName: &fn}); err == nil {
		for _, a := range als.Aliases {
			cfg := map[string]any{
				"function_name":    fn,
				"name":             aws.ToString(a.Name),
				"function_version": aws.ToString(a.FunctionVersion),
			}
			if v := aws.ToString(a.Description); v != "" {
				cfg["description"] = v
			}
			// weighted/canary alias routing -- a real, fairly common
			// traffic-shifting feature (gradual deploys).
			if rc := a.RoutingConfig; rc != nil && len(rc.AdditionalVersionWeights) > 0 {
				weights := make(map[string]any, len(rc.AdditionalVersionWeights))
				for version, weight := range rc.AdditionalVersionWeights {
					weights[version] = weight
				}
				cfg["routing_config"] = []any{map[string]any{"additional_version_weights": weights}}
			}
			kids = append(kids, model.Resource{
				Service: "lambda", Type: "alias", TFType: "aws_lambda_alias",
				Region: parent.Region, Account: parent.Account,
				ID:     fn + "/" + aws.ToString(a.Name),
				Config: cfg,
			})
		}
	}

	if urls, err := cl.ListFunctionUrlConfigs(ctx, &lambda.ListFunctionUrlConfigsInput{FunctionName: &fn}); err == nil {
		sch, serr := schemaFor("aws_lambda_function_url")
		for _, u := range urls.FunctionUrlConfigs {
			var cfg map[string]any
			if serr == nil {
				// AuthType doesn't snake-case to the schema's Required
				// "authorization_type" (an override, not an acronym-mangling
				// issue) -- Generic() still returns a non-nil cfg without
				// it, silently missing the field entirely rather than
				// falling back to anything. Confirmed by a real "Missing
				// required argument" tofu validate failure, not assumed.
				cfg, _ = Generic(u, sch, map[string]string{"function_arn": "function_name", "auth_type": "authorization_type"})
			}
			if cfg == nil {
				cfg = map[string]any{}
			}
			cfg["authorization_type"] = string(u.AuthType)
			cfg["function_name"] = fn
			id := fn
			if q := lambdaArnQualifier(aws.ToString(u.FunctionArn), fn); q != "" {
				cfg["qualifier"] = q
				// "/"-joined, not ":" -- confirmed against the real
				// provider's own functionURLResourceIDSeparator (unlike
				// function_event_invoke_config just below, which really
				// is ":"-joined). Using the wrong separator here doesn't
				// error at import time -- it silently parses as a single,
				// unqualified function_name and leaves qualifier empty,
				// surfacing only as a forced replacement on the very next
				// plan. Confirmed by a real tofu plan showing exactly that
				// (function_name coming back as the combined "name:live"
				// string, qualifier absent), not assumed from reading the
				// source alone.
				id = fn + "/" + q
			}
			kids = append(kids, model.Resource{
				Service: "lambda", Type: "function-url", TFType: "aws_lambda_function_url",
				Region: parent.Region, Account: parent.Account,
				ID: id, ImportID: id,
				Config: cfg,
			})
		}
	}

	if eics, err := cl.ListFunctionEventInvokeConfigs(ctx, &lambda.ListFunctionEventInvokeConfigsInput{FunctionName: &fn}); err == nil {
		sch, serr := schemaFor("aws_lambda_function_event_invoke_config")
		for _, e := range eics.FunctionEventInvokeConfigs {
			var cfg map[string]any
			if serr == nil {
				cfg, _ = Generic(e, sch, map[string]string{"function_arn": "function_name"})
			}
			if cfg == nil {
				cfg = map[string]any{}
			}
			cfg["function_name"] = fn
			id := fn
			if q := lambdaArnQualifier(aws.ToString(e.FunctionArn), fn); q != "" {
				cfg["qualifier"] = q
				id = fn + ":" + q
			}
			kids = append(kids, model.Resource{
				Service: "lambda", Type: "function-event-invoke-config", TFType: "aws_lambda_function_event_invoke_config",
				Region: parent.Region, Account: parent.Account,
				ID: id, ImportID: id,
				Config: cfg,
			})
		}
	}

	if pccs, err := cl.ListProvisionedConcurrencyConfigs(ctx, &lambda.ListProvisionedConcurrencyConfigsInput{FunctionName: &fn}); err == nil {
		for _, p := range pccs.ProvisionedConcurrencyConfigs {
			q := lambdaArnQualifier(aws.ToString(p.FunctionArn), fn)
			if q == "" {
				continue
			}
			// ","-joined -- this type goes through the provider's shared
			// flex.FlattenResourceId helper (ResourceIdSeparator = ","),
			// not the ":" convention several sibling Lambda types use.
			id := fn + "," + q
			kids = append(kids, model.Resource{
				Service: "lambda", Type: "provisioned-concurrency-config", TFType: "aws_lambda_provisioned_concurrency_config",
				Region: parent.Region, Account: parent.Account,
				ID: id, ImportID: id,
				Config: map[string]any{
					"function_name":                     fn,
					"qualifier":                         q,
					"provisioned_concurrent_executions": aws.ToInt32(p.RequestedProvisionedConcurrentExecutions),
				},
			})
		}
	}

	if rc, err := cl.GetFunctionRecursionConfig(ctx, &lambda.GetFunctionRecursionConfigInput{FunctionName: &fn}); err == nil {
		kids = append(kids, model.Resource{
			Service: "lambda", Type: "function-recursion-config", TFType: "aws_lambda_function_recursion_config",
			Region: parent.Region, Account: parent.Account,
			ID: fn, ImportID: fn,
			Config: map[string]any{
				"function_name":  fn,
				"recursive_loop": string(rc.RecursiveLoop),
			},
		})
	}

	return kids, nil
}

// lambdaArnQualifier returns the version/alias suffix on a qualified Lambda
// ARN ("...function:name:1" / "...function:name:LIVE"), or "" for a bare,
// unqualified function ARN ("...function:name").
func lambdaArnQualifier(arn, functionName string) string {
	suffix := ":" + functionName + ":"
	if i := strings.Index(arn, suffix); i >= 0 {
		return arn[i+len(suffix):]
	}
	return ""
}

// fixSelfManagedEndpoints repairs self_managed_event_source.endpoints in
// place: map(string) in the schema (one comma-joined string of bootstrap
// servers per key, per AWS's own docs), but GetEventSourceMappingConfiguration
// returns map[string][]string. Generic()'s IsMap() handling passes a
// map-typed value through untouched on the assumption the SDK shape already
// matches the schema's -- it doesn't here, so left alone this would emit a
// map of string-lists where the provider expects a map of plain strings.
func fixSelfManagedEndpoints(cfg map[string]any) {
	sms, ok := cfg["self_managed_event_source"].([]any)
	if !ok || len(sms) != 1 {
		return
	}
	m0, ok := sms[0].(map[string]any)
	if !ok {
		return
	}
	ep, ok := m0["endpoints"].(map[string]any)
	if !ok {
		return
	}
	fixed := make(map[string]any, len(ep))
	for k, v := range ep {
		list, ok := v.([]any)
		if !ok {
			fixed[k] = v
			continue
		}
		parts := make([]string, len(list))
		for i, e := range list {
			parts[i], _ = e.(string)
		}
		fixed[k] = strings.Join(parts, ",")
	}
	m0["endpoints"] = fixed
}
