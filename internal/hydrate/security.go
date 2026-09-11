package hydrate

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/acm"
	"github.com/aws/aws-sdk-go-v2/service/configservice"
	"github.com/aws/aws-sdk-go-v2/service/guardduty"
	guarddutytypes "github.com/aws/aws-sdk-go-v2/service/guardduty/types"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/ram"
	sm "github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/virtualbeck/inherit/model"
)

func init() {
	register("aws_kms_key", hydrateKMSKey)
	register("aws_secretsmanager_secret", hydrateSecret)
	register("aws_acm_certificate", hydrateACM)
	register("aws_guardduty_detector", hydrateGuardDutyDetector)
	register("aws_config_config_rule", hydrateConfigRule)
	register("aws_ram_resource_share", hydrateRAMShare)
}

func hydrateKMSKey(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	sch, err := schemaFor("aws_kms_key")
	if err != nil {
		return nil, err
	}
	cl := kms.NewFromConfig(c.Cfg(r.Region))
	out, err := cl.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: &r.ID})
	if err != nil {
		return nil, err
	}
	m := out.KeyMetadata
	if m == nil {
		return nil, fmt.Errorf("not found")
	}
	// AWS-managed keys (KeyManager AWS) and replicas of an external primary
	// cannot be managed by Terraform.
	if string(m.KeyManager) == "AWS" {
		return nil, fmt.Errorf("AWS-managed KMS key")
	}
	// A key scheduled for deletion still answers DescribeKey (and stays
	// visible to the tagging-API sweep until it's actually gone), but it's
	// disabled and about to disappear -- not a real importable resource,
	// same "discovered but not really there" shape as an INACTIVE ECS
	// cluster.
	if string(m.KeyState) == "PendingDeletion" {
		return nil, fmt.Errorf("KMS key pending deletion")
	}
	// The provider reads the key policy on every plan; if this principal can't
	// (the key's own policy denies kms:GetKeyPolicy) the plan would fail, so
	// leave the key out rather than emit an un-plannable resource. The
	// document itself (unlike IAM's, not URL-encoded) is real, recoverable
	// data that was being thrown away here -- `policy` is Optional+Computed,
	// so omitting it doesn't diff, but the whole point of this tool is to
	// surface what's actually there rather than let it go computed-invisible.
	pol := "default"
	gkp, err := cl.GetKeyPolicy(ctx, &kms.GetKeyPolicyInput{KeyId: &r.ID, PolicyName: &pol})
	if err != nil {
		return nil, fmt.Errorf("key policy not readable: %w", err)
	}
	cfg, err := Generic(m, sch, map[string]string{"key_spec": "customer_master_key_spec"})
	if err != nil {
		return nil, err
	}
	if doc := aws.ToString(gkp.Policy); doc != "" {
		cfg["policy"] = doc
	}
	// KeyMetadata carries no rotation field at all -- it's a separate call,
	// and the schema default (false) means omitting it here is read by
	// Terraform as "turn rotation off", diffing against a real key that
	// actually has it on.
	if rot, rerr := cl.GetKeyRotationStatus(ctx, &kms.GetKeyRotationStatusInput{KeyId: &r.ID}); rerr == nil {
		cfg["enable_key_rotation"] = rot.KeyRotationEnabled
	}
	return cfg, nil
}

func hydrateSecret(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	sch, err := schemaFor("aws_secretsmanager_secret")
	if err != nil {
		return nil, err
	}
	out, err := sm.NewFromConfig(c.Cfg(r.Region)).DescribeSecret(ctx, &sm.DescribeSecretInput{SecretId: &r.ARN})
	if err != nil {
		return nil, err
	}
	cfg, err := Generic(out, sch, nil)
	if err != nil {
		return nil, err
	}
	// DescribeSecretOutput has no "Policy" field at all, so Generic() never
	// populates the schema's Optional+Computed `policy` attribute here --
	// that's already correct: the real policy is emitted as its own
	// aws_secretsmanager_secret_policy resource (fanoutSecretPolicy), and
	// setting both would be two resources fighting over the same attachment.
	//
	// ReplicationStatus (cross-region replicas) isn't part of the flat
	// struct Generic() walks -- it's a real, recoverable list Generic()
	// never sees the shape of.
	var replicas []any
	for _, rs := range out.ReplicationStatus {
		region := aws.ToString(rs.Region)
		if region == "" {
			continue
		}
		rep := map[string]any{"region": region}
		if k := aws.ToString(rs.KmsKeyId); k != "" {
			rep["kms_key_id"] = k
		}
		replicas = append(replicas, rep)
	}
	if len(replicas) > 0 {
		cfg["replica"] = replicas
	}
	return cfg, nil
}

func hydrateACM(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	out, err := acm.NewFromConfig(c.Cfg(r.Region)).DescribeCertificate(ctx, &acm.DescribeCertificateInput{CertificateArn: &r.ARN})
	if err != nil {
		return nil, err
	}
	sch, err := schemaFor("aws_acm_certificate")
	if err != nil {
		return nil, err
	}
	cfg, err := Generic(out.Certificate, sch, nil)
	if err != nil {
		return nil, err
	}
	// A real account returned "RSA-2048" (hyphen) for key_algorithm on an
	// older/imported certificate; the SDK's own enum constants (and the
	// provider's validator) only recognize the underscore form ("RSA_2048").
	// DescribeCertificate's KeyAlgorithm is a bare string type with no
	// server-side normalization, so ACM itself is inconsistent here, not us --
	// normalize on the way out.
	if v, ok := cfg["key_algorithm"].(string); ok {
		cfg["key_algorithm"] = strings.ReplaceAll(v, "-", "_")
	}
	return cfg, nil
}

func hydrateGuardDutyDetector(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	id := r.ID
	if _, rest, ok := strings.Cut(r.ID, "/"); ok {
		id = rest
	}
	out, err := guardduty.NewFromConfig(c.Cfg(r.Region)).GetDetector(ctx, &guardduty.GetDetectorInput{DetectorId: &id})
	if err != nil {
		return nil, err
	}
	cfg := map[string]any{"enable": string(out.Status) == "ENABLED"}
	if v := string(out.FindingPublishingFrequency); v != "" {
		cfg["finding_publishing_frequency"] = v
	}
	// DataSources is deprecated in favor of Features, but the vendored
	// provider schema for this resource only models the older datasources{}
	// block (Features is its own separate aws_guardduty_detector_feature
	// resource, not registered here) -- so this is still the real,
	// recoverable value for what this schema expects.
	if ds := out.DataSources; ds != nil {
		block := map[string]any{}
		if k := ds.Kubernetes; k != nil && k.AuditLogs != nil {
			block["kubernetes"] = map[string]any{
				"audit_logs": map[string]any{"enable": k.AuditLogs.Status == guarddutytypes.DataSourceStatusEnabled},
			}
		}
		if mp := ds.MalwareProtection; mp != nil && mp.ScanEc2InstanceWithFindings != nil && mp.ScanEc2InstanceWithFindings.EbsVolumes != nil {
			block["malware_protection"] = map[string]any{
				"scan_ec2_instance_with_findings": map[string]any{
					"ebs_volumes": map[string]any{"enable": mp.ScanEc2InstanceWithFindings.EbsVolumes.Status == guarddutytypes.DataSourceStatusEnabled},
				},
			}
		}
		if s3 := ds.S3Logs; s3 != nil {
			block["s3_logs"] = map[string]any{"enable": s3.Status == guarddutytypes.DataSourceStatusEnabled}
		}
		if len(block) > 0 {
			cfg["datasources"] = []any{block}
		}
	}
	return cfg, nil
}

func hydrateConfigRule(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	name := r.ID
	if _, rest, ok := strings.Cut(r.ID, "/"); ok { // ARN id is "config-rule/config-rule-xxxx"
		name = rest
	}
	out, err := configservice.NewFromConfig(c.Cfg(r.Region)).DescribeConfigRules(ctx, &configservice.DescribeConfigRulesInput{
		ConfigRuleNames: []string{name},
	})
	if err != nil {
		return nil, err
	}
	if len(out.ConfigRules) == 0 {
		return nil, fmt.Errorf("not found")
	}
	rule := out.ConfigRules[0]
	// ControlTower / Security Hub manage their own rules; adopting them fights
	// the managing service.
	if rule.CreatedBy != nil && aws.ToString(rule.CreatedBy) != "" {
		return nil, fmt.Errorf("service-managed rule (%s)", aws.ToString(rule.CreatedBy))
	}
	cfg := map[string]any{"name": aws.ToString(rule.ConfigRuleName)}
	if v := aws.ToString(rule.Description); v != "" {
		cfg["description"] = v
	}
	if src := rule.Source; src != nil {
		s := map[string]any{"owner": string(src.Owner)}
		if v := aws.ToString(src.SourceIdentifier); v != "" {
			s["source_identifier"] = v
		}
		cfg["source"] = s
	}
	if rule.InputParameters != nil && aws.ToString(rule.InputParameters) != "" {
		cfg["input_parameters"] = aws.ToString(rule.InputParameters)
	}
	if rule.Scope != nil && len(rule.Scope.ComplianceResourceTypes) > 0 {
		cfg["scope"] = map[string]any{"compliance_resource_types": toAny(rule.Scope.ComplianceResourceTypes)}
	}
	if v := string(rule.MaximumExecutionFrequency); v != "" {
		cfg["maximum_execution_frequency"] = v
	}
	if len(rule.EvaluationModes) > 0 {
		var ems []any
		for _, em := range rule.EvaluationModes {
			ems = append(ems, map[string]any{"mode": string(em.Mode)})
		}
		cfg["evaluation_mode"] = ems
	}
	if src := rule.Source; src != nil && len(src.SourceDetails) > 0 {
		s, _ := cfg["source"].(map[string]any)
		var sds []any
		for _, sd := range src.SourceDetails {
			m := map[string]any{}
			if v := string(sd.EventSource); v != "" {
				m["event_source"] = v
			}
			if v := string(sd.MessageType); v != "" {
				m["message_type"] = v
			}
			if v := string(sd.MaximumExecutionFrequency); v != "" {
				m["maximum_execution_frequency"] = v
			}
			sds = append(sds, m)
		}
		s["source_detail"] = sds
		cfg["source"] = s
	}
	return cfg, nil
}

func hydrateRAMShare(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	arn := r.ARN
	out, err := ram.NewFromConfig(c.Cfg(r.Region)).GetResourceShares(ctx, &ram.GetResourceSharesInput{
		ResourceShareArns: []string{arn},
		ResourceOwner:     "SELF",
	})
	if err != nil {
		return nil, err
	}
	if len(out.ResourceShares) == 0 {
		return nil, fmt.Errorf("not found")
	}
	s := out.ResourceShares[0]
	cfg := map[string]any{"name": aws.ToString(s.Name)}
	if s.AllowExternalPrincipals != nil {
		cfg["allow_external_principals"] = *s.AllowExternalPrincipals
	}
	// managed permission ARNs are a separate call, not part of ResourceShare
	// itself; a share using anything but each resource type's default
	// managed permission needs this to avoid a permanent diff.
	if perms, perr := ram.NewFromConfig(c.Cfg(r.Region)).ListResourceSharePermissions(ctx, &ram.ListResourceSharePermissionsInput{
		ResourceShareArn: &arn,
	}); perr == nil && len(perms.Permissions) > 0 {
		var arns []any
		for _, p := range perms.Permissions {
			if v := aws.ToString(p.Arn); v != "" {
				arns = append(arns, v)
			}
		}
		if len(arns) > 0 {
			cfg["permission_arns"] = arns
		}
	}
	return cfg, nil
}
