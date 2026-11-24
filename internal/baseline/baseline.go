// Package baseline marks resources that organization governance stamps into every account and region.
package baseline

import (
	"regexp"
	"strings"

	"github.com/virtualbeck/inherit/model"
)

const (
	ControlTower   = "control-tower"
	QuickSetup     = "ssm-quick-setup"
	StackSet       = "stackset"
	GuardDuty      = "guardduty-managed"
	AccountSetting = "account-setting"
	UserPattern    = "user-pattern"
)

var (
	controlTowerRe = regexp.MustCompile(`(?i)aws-controltower|AWSControlTower`)
	quickSetupRe   = regexp.MustCompile(`AWSQuickSetup|AWS-QuickSetup`)
	stackSetRe     = regexp.MustCompile(`^StackSet-`)
	guardDutyRe    = regexp.MustCompile(`^AmazonGuardDuty-`)
)

// Per-account governance settings; a resource explorer view counts only as AWS's DefaultView.
var accountSettings = map[string]func(model.Resource) bool{
	"aws_securityhub_account":            func(model.Resource) bool { return true },
	"aws_securityhub_finding_aggregator": func(model.Resource) bool { return true },
	"aws_resourceexplorer2_index":        func(model.Resource) bool { return true },
	"aws_resourceexplorer2_view":         func(r model.Resource) bool { return cfgString(r, "name") == "DefaultView" },
	"aws_ssm_service_setting":            func(model.Resource) bool { return true },
}

// Child types and the attribute naming their parent.
var parentAttr = map[string]string{
	"aws_lambda_function_recursion_config":    "function_name",
	"aws_lambda_permission":                   "function_name",
	"aws_lambda_function_event_invoke_config": "function_name",
	"aws_sns_topic_policy":                    "arn",
	"aws_sns_topic_subscription":              "topic_arn",
	"aws_cloudwatch_event_target":             "rule",
}

// Mark sets Resource.Baseline for organization baseline and returns counts per reason. Patterns match any string the resource holds.
func Mark(inv *model.Inventory, patterns []*regexp.Regexp) map[string]int {
	counts := map[string]int{}
	parents := map[string]string{} // region + "\x00" + identity -> reason
	for i := range inv.Resources {
		r := &inv.Resources[i]
		if reason := builtIn(*r); reason != "" {
			r.Baseline = reason
		} else if matchesAny(*r, patterns) {
			r.Baseline = UserPattern
		}
		if r.Baseline != "" {
			for _, id := range identities(*r) {
				parents[r.Region+"\x00"+id] = r.Baseline
			}
		}
	}
	for i := range inv.Resources {
		r := &inv.Resources[i]
		if r.Baseline == "" {
			r.Baseline = inherited(*r, parents)
		}
		if r.Baseline != "" {
			counts[r.Baseline]++
		}
	}
	return counts
}

func builtIn(r model.Resource) string {
	ids := identities(r)
	switch {
	case anyMatch(controlTowerRe, ids):
		return ControlTower
	case anyMatch(quickSetupRe, ids) || hasTagPrefix(r, "QuickSetup"):
		return QuickSetup
	case anyMatch(stackSetRe, ids):
		return StackSet
	case r.TFType == "aws_ssm_association" && (guardDutyRe.MatchString(cfgString(r, "name")) || r.Tags["GuardDutyManaged"] == "true"):
		return GuardDuty
	}
	if is, ok := accountSettings[r.TFType]; ok && is(r) {
		return AccountSetting
	}
	return ""
}

func inherited(r model.Resource, parents map[string]string) string {
	ref := ""
	if attr, ok := parentAttr[r.TFType]; ok {
		ref = cfgString(r, attr)
	} else if r.TFType == "aws_cloudwatch_log_group" {
		ref, _ = strings.CutPrefix(cfgString(r, "name"), "/aws/lambda/")
	}
	if ref == "" {
		return ""
	}
	if reason, ok := parents[r.Region+"\x00"+ref]; ok {
		return reason
	}
	return parents[r.Region+"\x00"+ref[strings.LastIndexByte(ref, ':')+1:]]
}

// The strings a resource is known by: ID, ARN and its name attributes.
func identities(r model.Resource) []string {
	out := []string{r.ID, r.ARN}
	for _, k := range []string{"name", "function_name", "association_name"} {
		if v := cfgString(r, k); v != "" {
			out = append(out, v)
		}
	}
	return out
}

func anyMatch(re *regexp.Regexp, ss []string) bool {
	for _, s := range ss {
		if s != "" && re.MatchString(s) {
			return true
		}
	}
	return false
}

func hasTagPrefix(r model.Resource, prefix string) bool {
	for k := range r.Tags {
		if strings.HasPrefix(k, prefix) {
			return true
		}
	}
	return false
}

func matchesAny(r model.Resource, patterns []*regexp.Regexp) bool {
	if len(patterns) == 0 {
		return false
	}
	found := false
	walk(r.Config, func(s string) {
		for _, p := range patterns {
			if p.MatchString(s) {
				found = true
			}
		}
	})
	for _, p := range patterns {
		if anyMatch(p, []string{r.ID, r.ARN}) {
			found = true
		}
	}
	return found
}

func walk(v any, f func(string)) {
	switch t := v.(type) {
	case string:
		f(t)
	case map[string]any:
		for _, e := range t {
			walk(e, f)
		}
	case []any:
		for _, e := range t {
			walk(e, f)
		}
	}
}

func cfgString(r model.Resource, key string) string {
	s, _ := r.Config[key].(string)
	return s
}
