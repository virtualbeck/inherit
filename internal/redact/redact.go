// Package redact moves secrets out of the inventory.
package redact

import (
	"fmt"
	"regexp"

	"github.com/virtualbeck/inherit/model"
)

// AKIA: long-term key; ASIA: temporary STS key.
var accessKeyRe = regexp.MustCompile(`^(?:AKIA|ASIA)[A-Z0-9]{16}$`)

// Sentinel marks a redacted value for ignore_changes.
const Sentinel = "__inherit_redacted__"

// Secret is one removed value, keyed by ARN+path.
type Secret struct {
	ResourceARN string `json:"resource_arn"`
	TFType      string `json:"tf_type"`
	Path        string `json:"path"`
	Value       string `json:"value"`
}

// Split redacts inv in place, returning removed values.
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
		redactAccessKeyIDs(*r, r.Config, add)
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

// Generic() yields environment as list or map.
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

// Key IDs can appear anywhere, so scan everything.
func redactAccessKeyIDs(r model.Resource, cfg map[string]any, add func(model.Resource, string, string)) {
	redactAccessKeyIDsAt(r, cfg, "", add)
}

func redactAccessKeyIDsAt(r model.Resource, v any, path string, add func(model.Resource, string, string)) {
	switch m := v.(type) {
	case map[string]any:
		n := 0
		renames := map[string]string{}
		for k, val := range m {
			sub := joinPath(path, k)
			if accessKeyRe.MatchString(k) {
				n++
				add(r, sub+".key", k)
				renames[k] = fmt.Sprintf("%s_key_%d", Sentinel, n)
			}
			if s, ok := val.(string); ok {
				if s != Sentinel && accessKeyRe.MatchString(s) {
					add(r, sub, s)
					m[k] = Sentinel
				}
			} else {
				redactAccessKeyIDsAt(r, val, sub, add)
			}
		}
		for old, nw := range renames {
			m[nw] = m[old]
			delete(m, old)
		}
	case map[string]string:
		n := 0
		renames := map[string]string{}
		for k, val := range m {
			sub := joinPath(path, k)
			if accessKeyRe.MatchString(k) {
				n++
				add(r, sub+".key", k)
				renames[k] = fmt.Sprintf("%s_key_%d", Sentinel, n)
			}
			if val != Sentinel && accessKeyRe.MatchString(val) {
				add(r, sub, val)
				m[k] = Sentinel
			}
		}
		for old, nw := range renames {
			m[nw] = m[old]
			delete(m, old)
		}
	case []any:
		for i, e := range m {
			redactAccessKeyIDsAt(r, e, fmt.Sprintf("%s[%d]", path, i), add)
		}
	}
}

func joinPath(path, key string) string {
	if path == "" {
		return key
	}
	return path + "." + key
}
