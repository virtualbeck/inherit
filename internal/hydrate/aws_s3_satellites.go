package hydrate

import (
	"context"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/virtualbeck/inherit-core/model"
)

func init() {
	registerFanout("aws_s3_bucket", fanoutS3)
}

// fanoutS3 emits the aws_s3_bucket_* sub-resources the provider models
// separately (versioning, encryption, public access block, policy, ownership).
// Each GetBucket* call fails cleanly when that feature isn't configured; those
// are skipped. All import with the bucket name.
func fanoutS3(ctx context.Context, c *Clients, parent model.Resource) ([]model.Resource, error) {
	bucket := parent.ID
	region := bucketRegion(ctx, c, bucket)
	cl := s3.NewFromConfig(c.Cfg(region))

	mk := func(tfType string, cfg map[string]any) model.Resource {
		cfg["bucket"] = bucket
		return model.Resource{
			Service: "s3", Type: "bucket-config", TFType: tfType,
			Region: region, Account: parent.Account, ID: bucket, Config: cfg,
		}
	}
	var kids []model.Resource

	if v, err := cl.GetBucketVersioning(ctx, &s3.GetBucketVersioningInput{Bucket: &bucket}); err == nil && v.Status != "" {
		kids = append(kids, mk("aws_s3_bucket_versioning", map[string]any{
			"versioning_configuration": map[string]any{"status": string(v.Status)},
		}))
	}

	if e, err := cl.GetBucketEncryption(ctx, &s3.GetBucketEncryptionInput{Bucket: &bucket}); err == nil && e.ServerSideEncryptionConfiguration != nil {
		var rules []any
		for _, r := range e.ServerSideEncryptionConfiguration.Rules {
			rule := map[string]any{}
			if d := r.ApplyServerSideEncryptionByDefault; d != nil {
				def := map[string]any{"sse_algorithm": string(d.SSEAlgorithm)}
				if k := aws.ToString(d.KMSMasterKeyID); k != "" {
					def["kms_master_key_id"] = k
				}
				rule["apply_server_side_encryption_by_default"] = def
			}
			if r.BucketKeyEnabled != nil {
				rule["bucket_key_enabled"] = *r.BucketKeyEnabled
			}
			rules = append(rules, rule)
		}
		if len(rules) > 0 {
			kids = append(kids, mk("aws_s3_bucket_server_side_encryption_configuration", map[string]any{"rule": rules}))
		}
	}

	if p, err := cl.GetPublicAccessBlock(ctx, &s3.GetPublicAccessBlockInput{Bucket: &bucket}); err == nil && p.PublicAccessBlockConfiguration != nil {
		cfgp := p.PublicAccessBlockConfiguration
		kids = append(kids, mk("aws_s3_bucket_public_access_block", map[string]any{
			"block_public_acls":       aws.ToBool(cfgp.BlockPublicAcls),
			"block_public_policy":     aws.ToBool(cfgp.BlockPublicPolicy),
			"ignore_public_acls":      aws.ToBool(cfgp.IgnorePublicAcls),
			"restrict_public_buckets": aws.ToBool(cfgp.RestrictPublicBuckets),
		}))
	}

	if pol, err := cl.GetBucketPolicy(ctx, &s3.GetBucketPolicyInput{Bucket: &bucket}); err == nil && aws.ToString(pol.Policy) != "" {
		kids = append(kids, mk("aws_s3_bucket_policy", map[string]any{"policy": aws.ToString(pol.Policy)}))
	}

	if oc, err := cl.GetBucketOwnershipControls(ctx, &s3.GetBucketOwnershipControlsInput{Bucket: &bucket}); err == nil && oc.OwnershipControls != nil {
		var rules []any
		for _, r := range oc.OwnershipControls.Rules {
			rules = append(rules, map[string]any{"object_ownership": string(r.ObjectOwnership)})
		}
		if len(rules) > 0 {
			kids = append(kids, mk("aws_s3_bucket_ownership_controls", map[string]any{"rule": rules}))
		}
	}

	if lc, err := cl.GetBucketLifecycleConfiguration(ctx, &s3.GetBucketLifecycleConfigurationInput{Bucket: &bucket}); err == nil && len(lc.Rules) > 0 {
		var rules []any
		for _, r := range lc.Rules {
			rule := map[string]any{
				"id":     aws.ToString(r.ID),
				"status": string(r.Status),
			}
			rule["filter"] = s3LifecycleFilter(r.Filter)
			if r.Expiration != nil {
				exp := map[string]any{}
				if r.Expiration.Days != nil {
					exp["days"] = *r.Expiration.Days
				}
				if len(exp) > 0 {
					rule["expiration"] = exp
				}
			}
			var trans []any
			for _, t := range r.Transitions {
				tr := map[string]any{"storage_class": string(t.StorageClass)}
				if t.Days != nil {
					tr["days"] = *t.Days
				}
				trans = append(trans, tr)
			}
			if len(trans) > 0 {
				rule["transition"] = trans
			}
			if a := r.AbortIncompleteMultipartUpload; a != nil && a.DaysAfterInitiation != nil {
				rule["abort_incomplete_multipart_upload"] = map[string]any{
					"days_after_initiation": *a.DaysAfterInitiation,
				}
			}
			if r.NoncurrentVersionExpiration != nil && r.NoncurrentVersionExpiration.NoncurrentDays != nil {
				nve := map[string]any{"noncurrent_days": *r.NoncurrentVersionExpiration.NoncurrentDays}
				if v := r.NoncurrentVersionExpiration.NewerNoncurrentVersions; v != nil {
					nve["newer_noncurrent_versions"] = *v
				}
				rule["noncurrent_version_expiration"] = nve
			}
			var nvts []any
			for _, t := range r.NoncurrentVersionTransitions {
				nvt := map[string]any{"storage_class": string(t.StorageClass)}
				if t.NoncurrentDays != nil {
					nvt["noncurrent_days"] = *t.NoncurrentDays
				}
				if t.NewerNoncurrentVersions != nil {
					nvt["newer_noncurrent_versions"] = *t.NewerNoncurrentVersions
				}
				nvts = append(nvts, nvt)
			}
			if len(nvts) > 0 {
				rule["noncurrent_version_transition"] = nvts
			}
			rules = append(rules, rule)
		}
		kids = append(kids, mk("aws_s3_bucket_lifecycle_configuration", map[string]any{"rule": rules}))
	}

	if cors, err := cl.GetBucketCors(ctx, &s3.GetBucketCorsInput{Bucket: &bucket}); err == nil && len(cors.CORSRules) > 0 {
		var rules []any
		for _, r := range cors.CORSRules {
			cr := map[string]any{
				"allowed_methods": toAny(r.AllowedMethods),
				"allowed_origins": toAny(r.AllowedOrigins),
			}
			if len(r.AllowedHeaders) > 0 {
				cr["allowed_headers"] = toAny(r.AllowedHeaders)
			}
			if len(r.ExposeHeaders) > 0 {
				cr["expose_headers"] = toAny(r.ExposeHeaders)
			}
			if r.MaxAgeSeconds != nil {
				cr["max_age_seconds"] = *r.MaxAgeSeconds
			}
			rules = append(rules, cr)
		}
		kids = append(kids, mk("aws_s3_bucket_cors_configuration", map[string]any{"cors_rule": rules}))
	}

	if web, err := cl.GetBucketWebsite(ctx, &s3.GetBucketWebsiteInput{Bucket: &bucket}); err == nil && (web.IndexDocument != nil || web.RedirectAllRequestsTo != nil) {
		wcfg := map[string]any{}
		if web.IndexDocument != nil {
			wcfg["index_document"] = map[string]any{"suffix": aws.ToString(web.IndexDocument.Suffix)}
		}
		if web.ErrorDocument != nil {
			wcfg["error_document"] = map[string]any{"key": aws.ToString(web.ErrorDocument.Key)}
		}
		if web.RedirectAllRequestsTo != nil {
			wcfg["redirect_all_requests_to"] = map[string]any{
				"host_name": aws.ToString(web.RedirectAllRequestsTo.HostName),
			}
		}
		kids = append(kids, mk("aws_s3_bucket_website_configuration", wcfg))
	}

	if lg, err := cl.GetBucketLogging(ctx, &s3.GetBucketLoggingInput{Bucket: &bucket}); err == nil && lg.LoggingEnabled != nil {
		kids = append(kids, mk("aws_s3_bucket_logging", map[string]any{
			"target_bucket": aws.ToString(lg.LoggingEnabled.TargetBucket),
			"target_prefix": aws.ToString(lg.LoggingEnabled.TargetPrefix),
		}))
	}

	if ac, err := cl.GetBucketAccelerateConfiguration(ctx, &s3.GetBucketAccelerateConfigurationInput{Bucket: &bucket}); err == nil && ac.Status != "" {
		kids = append(kids, mk("aws_s3_bucket_accelerate_configuration", map[string]any{"status": string(ac.Status)}))
	}

	if rp, err := cl.GetBucketRequestPayment(ctx, &s3.GetBucketRequestPaymentInput{Bucket: &bucket}); err == nil && rp.Payer != "" {
		kids = append(kids, mk("aws_s3_bucket_request_payment_configuration", map[string]any{"payer": string(rp.Payer)}))
	}

	if n, err := cl.GetBucketNotificationConfiguration(ctx, &s3.GetBucketNotificationConfigurationInput{Bucket: &bucket}); err == nil {
		ncfg := map[string]any{}
		var topics, queues, lambdas []any
		for _, t := range n.TopicConfigurations {
			topics = append(topics, s3NotifyBlock(aws.ToString(t.TopicArn), "topic_arn", t.Events, t.Filter, aws.ToString(t.Id)))
		}
		for _, q := range n.QueueConfigurations {
			queues = append(queues, s3NotifyBlock(aws.ToString(q.QueueArn), "queue_arn", q.Events, q.Filter, aws.ToString(q.Id)))
		}
		for _, l := range n.LambdaFunctionConfigurations {
			lambdas = append(lambdas, s3NotifyBlock(aws.ToString(l.LambdaFunctionArn), "lambda_function_arn", l.Events, l.Filter, aws.ToString(l.Id)))
		}
		if len(topics) > 0 {
			ncfg["topic"] = topics
		}
		if len(queues) > 0 {
			ncfg["queue"] = queues
		}
		if len(lambdas) > 0 {
			ncfg["lambda_function"] = lambdas
		}
		// EventBridgeConfiguration's mere presence (a bare, empty struct
		// when enabled -- it carries no fields of its own) means
		// eventbridge notifications are on; nil means off. Confirmed as a
		// real gap by a live account: another feature (GuardDuty's Malware
		// Protection plan) had turned this on for the same bucket, and a
		// generated config missing it showed a perpetual
		// eventbridge=true->false diff on every plan.
		if n.EventBridgeConfiguration != nil {
			ncfg["eventbridge"] = true
		}
		if len(ncfg) > 0 {
			kids = append(kids, mk("aws_s3_bucket_notification", ncfg))
		}
	}

	if rc, err := cl.GetBucketReplication(ctx, &s3.GetBucketReplicationInput{Bucket: &bucket}); err == nil && rc.ReplicationConfiguration != nil {
		rcfg := rc.ReplicationConfiguration
		var rules []any
		for _, r := range rcfg.Rules {
			rule := map[string]any{"status": string(r.Status)}
			if r.ID != nil {
				rule["id"] = aws.ToString(r.ID)
			}
			if r.Priority != nil {
				rule["priority"] = *r.Priority
			}
			if r.Filter != nil {
				rule["filter"] = s3ReplicationFilter(r.Filter)
			} else if v := aws.ToString(r.Prefix); v != "" {
				rule["filter"] = map[string]any{"prefix": v}
			}
			if r.Destination != nil {
				d := map[string]any{"bucket": aws.ToString(r.Destination.Bucket)}
				if v := string(r.Destination.StorageClass); v != "" {
					d["storage_class"] = v
				}
				// cross-account replication: the destination bucket owner's
				// account id, only present when access_control_translation
				// is also in play (a same-account destination never sets it).
				if v := aws.ToString(r.Destination.Account); v != "" {
					d["account"] = v
				}
				if r.Destination.EncryptionConfiguration != nil {
					d["encryption_configuration"] = map[string]any{
						"replica_kms_key_id": aws.ToString(r.Destination.EncryptionConfiguration.ReplicaKmsKeyID),
					}
				}
				if act := r.Destination.AccessControlTranslation; act != nil {
					d["access_control_translation"] = map[string]any{"owner": string(act.Owner)}
				}
				if m := r.Destination.Metrics; m != nil {
					mm := map[string]any{"status": string(m.Status)}
					if m.EventThreshold != nil && m.EventThreshold.Minutes != nil {
						mm["event_threshold"] = map[string]any{"minutes": *m.EventThreshold.Minutes}
					}
					d["metrics"] = mm
				}
				if rt := r.Destination.ReplicationTime; rt != nil {
					rtm := map[string]any{"status": string(rt.Status)}
					if rt.Time != nil && rt.Time.Minutes != nil {
						rtm["time"] = map[string]any{"minutes": *rt.Time.Minutes}
					}
					d["replication_time"] = rtm
				}
				rule["destination"] = d
			}
			if r.DeleteMarkerReplication != nil {
				rule["delete_marker_replication"] = map[string]any{
					"status": string(r.DeleteMarkerReplication.Status),
				}
			}
			// SourceSelectionCriteria is required by the provider whenever a
			// destination.encryption_configuration is set (replicating
			// KMS-encrypted source objects needs sse_kms_encrypted_objects
			// explicitly enabled).
			if ssc := r.SourceSelectionCriteria; ssc != nil {
				sm := map[string]any{}
				if sk := ssc.SseKmsEncryptedObjects; sk != nil {
					sm["sse_kms_encrypted_objects"] = map[string]any{"status": string(sk.Status)}
				}
				if rmod := ssc.ReplicaModifications; rmod != nil {
					sm["replica_modifications"] = map[string]any{"status": string(rmod.Status)}
				}
				if len(sm) > 0 {
					rule["source_selection_criteria"] = sm
				}
			}
			if eor := r.ExistingObjectReplication; eor != nil {
				rule["existing_object_replication"] = map[string]any{"status": string(eor.Status)}
			}
			rules = append(rules, rule)
		}
		if len(rules) > 0 {
			kids = append(kids, mk("aws_s3_bucket_replication_configuration", map[string]any{
				"role": aws.ToString(rcfg.Role),
				"rule": rules,
			}))
		}
	}

	if ol, err := cl.GetObjectLockConfiguration(ctx, &s3.GetObjectLockConfigurationInput{Bucket: &bucket}); err == nil && ol.ObjectLockConfiguration != nil {
		olc := ol.ObjectLockConfiguration
		cfg := map[string]any{}
		if v := string(olc.ObjectLockEnabled); v != "" {
			cfg["object_lock_enabled"] = v
		}
		if olc.Rule != nil && olc.Rule.DefaultRetention != nil {
			dr := olc.Rule.DefaultRetention
			ret := map[string]any{}
			if v := string(dr.Mode); v != "" {
				ret["mode"] = v
			}
			if dr.Days != nil {
				ret["days"] = *dr.Days
			}
			if dr.Years != nil {
				ret["years"] = *dr.Years
			}
			if len(ret) > 0 {
				cfg["rule"] = []any{map[string]any{"default_retention": []any{ret}}}
			}
		}
		if len(cfg) > 0 {
			kids = append(kids, mk("aws_s3_bucket_object_lock_configuration", cfg))
		}
	}

	if it, err := cl.ListBucketIntelligentTieringConfigurations(ctx, &s3.ListBucketIntelligentTieringConfigurationsInput{Bucket: &bucket}); err == nil {
		for _, tc := range it.IntelligentTieringConfigurationList {
			var tierings []any
			for _, t := range tc.Tierings {
				tierings = append(tierings, map[string]any{
					"access_tier": string(t.AccessTier),
					"days":        aws.ToInt32(t.Days),
				})
			}
			if len(tierings) == 0 {
				continue
			}
			cfg := map[string]any{
				"name":    aws.ToString(tc.Id),
				"status":  string(tc.Status),
				"tiering": tierings,
			}
			if fm := s3TieringFilter(tc.Filter); len(fm) > 0 {
				cfg["filter"] = fm
			}
			r := mk("aws_s3_bucket_intelligent_tiering_configuration", cfg)
			r.ID = bucket + ":" + aws.ToString(tc.Id)
			r.ImportID = r.ID
			kids = append(kids, r)
		}
	}

	if acl, err := cl.GetBucketAcl(ctx, &s3.GetBucketAclInput{Bucket: &bucket}); err == nil {
		if a := s3ACLConfig(acl.Owner, acl.Grants); a != nil {
			kids = append(kids, mk("aws_s3_bucket_acl", a))
		}
	}

	return kids, nil
}

// s3TieringFilter flattens an intelligent-tiering filter into the schema's
// flat prefix+tags shape. The schema's filter{} has no nested and{} -- it's
// just a flat prefix+tags, same as the SDK's single-predicate fields -- so
// an And-operator's prefix/tags are merged straight in rather than dropped.
func s3TieringFilter(f *s3types.IntelligentTieringFilter) map[string]any {
	if f == nil {
		return nil
	}
	fm := map[string]any{}
	prefix, tags := aws.ToString(f.Prefix), map[string]string{}
	if f.Tag != nil {
		tags[aws.ToString(f.Tag.Key)] = aws.ToString(f.Tag.Value)
	}
	if f.And != nil {
		if prefix == "" {
			prefix = aws.ToString(f.And.Prefix)
		}
		for _, t := range f.And.Tags {
			tags[aws.ToString(t.Key)] = aws.ToString(t.Value)
		}
	}
	if prefix != "" {
		fm["prefix"] = prefix
	}
	if len(tags) > 0 {
		fm["tags"] = tags
	}
	return fm
}

// s3ACLConfig always builds the full access_control_policy{} form (owner +
// grants), never the canned "acl" string: GetBucketAcl's response can't be
// reverse-engineered into a canned ACL name, and access_control_policy is
// what the provider's own Read returns verbatim, so it's the only form
// guaranteed to match state exactly. Returns nil when the bucket has no
// grants at all (nothing recoverable).
func s3ACLConfig(owner *s3types.Owner, grants []s3types.Grant) map[string]any {
	if owner == nil {
		return nil
	}
	ownerCfg := map[string]any{"id": aws.ToString(owner.ID)}
	if v := aws.ToString(owner.DisplayName); v != "" {
		ownerCfg["display_name"] = v
	}
	var grantCfgs []any
	for _, g := range grants {
		if g.Grantee == nil {
			continue
		}
		grantee := map[string]any{"type": string(g.Grantee.Type)}
		if v := aws.ToString(g.Grantee.ID); v != "" {
			grantee["id"] = v
		}
		if v := aws.ToString(g.Grantee.URI); v != "" {
			grantee["uri"] = v
		}
		if v := aws.ToString(g.Grantee.EmailAddress); v != "" {
			grantee["email_address"] = v
		}
		if v := aws.ToString(g.Grantee.DisplayName); v != "" {
			grantee["display_name"] = v
		}
		grantCfgs = append(grantCfgs, map[string]any{
			"permission": string(g.Permission),
			"grantee":    []any{grantee},
		})
	}
	if len(grantCfgs) == 0 {
		return nil
	}
	return map[string]any{
		"access_control_policy": []any{map[string]any{
			"owner": []any{ownerCfg},
			"grant": grantCfgs,
		}},
	}
}

// s3LifecycleFilter builds a lifecycle rule's filter{} block. The provider
// accepts a bare prefix, a single tag, an and{} (multiple predicates
// combined), and/or object-size bounds -- all independently recoverable
// AWS-side conditions.
func s3LifecycleFilter(f *s3types.LifecycleRuleFilter) map[string]any {
	out := map[string]any{}
	if f == nil {
		return out
	}
	if v := aws.ToString(f.Prefix); v != "" {
		out["prefix"] = v
	}
	if f.ObjectSizeGreaterThan != nil {
		out["object_size_greater_than"] = *f.ObjectSizeGreaterThan
	}
	if f.ObjectSizeLessThan != nil {
		out["object_size_less_than"] = *f.ObjectSizeLessThan
	}
	if t := f.Tag; t != nil {
		out["tag"] = []any{map[string]any{"key": aws.ToString(t.Key), "value": aws.ToString(t.Value)}}
	}
	if a := f.And; a != nil {
		and := map[string]any{}
		if v := aws.ToString(a.Prefix); v != "" {
			and["prefix"] = v
		}
		if a.ObjectSizeGreaterThan != nil {
			and["object_size_greater_than"] = *a.ObjectSizeGreaterThan
		}
		if a.ObjectSizeLessThan != nil {
			and["object_size_less_than"] = *a.ObjectSizeLessThan
		}
		if len(a.Tags) > 0 {
			tags := map[string]any{}
			for _, t := range a.Tags {
				tags[aws.ToString(t.Key)] = aws.ToString(t.Value)
			}
			and["tags"] = tags
		}
		out["and"] = []any{and}
	}
	return out
}

// s3ReplicationFilter mirrors s3LifecycleFilter for replication rules: same
// prefix/tag/and shape, a distinct SDK type with no object-size bounds.
func s3ReplicationFilter(f *s3types.ReplicationRuleFilter) map[string]any {
	out := map[string]any{}
	if f == nil {
		return out
	}
	if v := aws.ToString(f.Prefix); v != "" {
		out["prefix"] = v
	}
	if t := f.Tag; t != nil {
		out["tag"] = []any{map[string]any{"key": aws.ToString(t.Key), "value": aws.ToString(t.Value)}}
	}
	if a := f.And; a != nil {
		and := map[string]any{}
		if v := aws.ToString(a.Prefix); v != "" {
			and["prefix"] = v
		}
		if len(a.Tags) > 0 {
			tags := map[string]any{}
			for _, t := range a.Tags {
				tags[aws.ToString(t.Key)] = aws.ToString(t.Value)
			}
			and["tags"] = tags
		}
		out["and"] = []any{and}
	}
	return out
}

func s3NotifyBlock(arn, arnKey string, events []s3types.Event, filter *s3types.NotificationConfigurationFilter, id string) map[string]any {
	b := map[string]any{arnKey: arn}
	var evs []any
	for _, e := range events {
		evs = append(evs, string(e))
	}
	if len(evs) > 0 {
		b["events"] = evs
	}
	if id != "" {
		b["id"] = id
	}
	if filter != nil && filter.Key != nil {
		for _, fr := range filter.Key.FilterRules {
			switch strings.ToLower(string(fr.Name)) {
			case "prefix":
				b["filter_prefix"] = aws.ToString(fr.Value)
			case "suffix":
				b["filter_suffix"] = aws.ToString(fr.Value)
			}
		}
	}
	return b
}
