// Package redact strips plaintext secrets out of a hydrated inventory before
// it leaves the user's machine. What's removed here is written to a local
// inventory.secrets.json instead (see Split); the uploaded inventory.json
// carries only the Sentinel in their place.
//
// The fields covered are the ones that legitimately end up in generated
// Terraform config but routinely hold secrets: Lambda env vars, EC2
// user_data, and plain (non-SecureString) SSM parameter values. Everything
// genuinely secret elsewhere (Secrets Manager values, RDS master passwords,
// SSM SecureString, ...) is already never read or already placeholdered by
// the hydrators.
//
// ECS container_definitions' environment[].value is deliberately NOT
// covered: unlike the fields above, there's no reliable signal to tell a
// real secret apart from ordinary plaintext config (log level, hostname,
// feature flags) short of guessing -- and guessing wrong in either
// direction is bad, either leaking a real secret or making every delivered
// project unreadable. AWS itself never treats this field as sensitive (it's
// plaintext in the live task definition to anyone with ecs:DescribeTaskDefinition;
// the actually-encrypted path is secrets[], already left alone below). A
// real secret placed in environment[] instead of secrets[] was already a
// mistake made outside this tool, in the live AWS account, before inherit
// ever saw it.
package redact

import (
	"github.com/virtualbeck/inherit/model"
)

// Sentinel replaces a redacted value in inventory.json. The backend
// recognizes it and emits the field with lifecycle.ignore_changes.
const Sentinel = "__inherit_redacted__"

// Secret is one removed value, keyed so inventory.secrets.json can be used
// to put it back: ResourceARN plus a dotted path into the resource's config.
type Secret struct {
	ResourceARN string `json:"resource_arn"`
	TFType      string `json:"tf_type"`
	Path        string `json:"path"`
	Value       string `json:"value"`
}

// Split walks inv in place, replacing covered values with Sentinel, and
// returns the removed values for inventory.secrets.json. Never nil, so the
// secrets file is always a valid JSON array.
func Split(inv *model.Inventory) []Secret {
	secrets := []Secret{}
	add := func(r model.Resource, path, val string) {
		secrets = append(secrets, Secret{ResourceARN: r.ARN, TFType: r.TFType, Path: path, Value: val})
	}

	for i := range inv.Resources {
		r := &inv.Resources[i]
		if r.Config == nil {
			continue
		}
		switch r.TFType {
		case "aws_lambda_function":
			redactLambdaEnv(*r, r.Config, add)
		case "aws_instance", "aws_launch_template":
			for _, k := range []string{"user_data", "user_data_base64"} {
				if s, ok := r.Config[k].(string); ok && s != "" && s != Sentinel {
					add(*r, k, s)
					r.Config[k] = Sentinel
				}
			}
		case "aws_ssm_parameter":
			if t, _ := r.Config["type"].(string); t != "SecureString" {
				if s, ok := r.Config["value"].(string); ok && s != "" && s != Sentinel {
					add(*r, "value", s)
					r.Config["value"] = Sentinel
				}
			}
		case "aws_cloudformation_stack":
			if m, ok := r.Config["parameters"].(map[string]any); ok {
				for k, v := range m {
					if s, ok := v.(string); ok && s != "" && s != Sentinel {
						add(*r, "parameters."+k, s)
						m[k] = Sentinel
					}
				}
			}
		}
	}
	return secrets
}

// redactLambdaEnv handles both shapes Generic() might produce for the
// environment block: a one-element []any of maps, or a bare map.
func redactLambdaEnv(r model.Resource, cfg map[string]any, add func(model.Resource, string, string)) {
	vars := lambdaEnvVars(cfg)
	if vars == nil {
		return
	}
	for k, v := range vars {
		if s, ok := v.(string); ok && s != Sentinel {
			add(r, "environment.variables."+k, s)
			vars[k] = Sentinel
		}
	}
}

func lambdaEnvVars(cfg map[string]any) map[string]any {
	env := cfg["environment"]
	switch e := env.(type) {
	case []any:
		if len(e) == 1 {
			if m, ok := e[0].(map[string]any); ok {
				if v, ok := m["variables"].(map[string]any); ok {
					return v
				}
			}
		}
	case map[string]any:
		if v, ok := e["variables"].(map[string]any); ok {
			return v
		}
	}
	return nil
}
