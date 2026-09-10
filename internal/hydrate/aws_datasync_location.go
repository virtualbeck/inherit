package hydrate

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/datasync"
	"github.com/virtualbeck/inherit-core/model"
)

// hydrateDataSyncLocation dispatches a discovered DataSync location to its
// real type. Every location type shares the SAME ARN resource segment
// ("location"), so the ARN alone can't tell them apart -- ListLocations'
// own LocationUri ("TYPE://GLOBAL_ID/SUBDIR", confirmed against the SDK's
// own doc comment) is the only signal, so this fetches that first, then
// retypes and delegates to the type-specific Describe call. Registered
// under aws_datasync_location_s3 as the placeholder (arbitrary; retype
// always fires for a real location).
//
// NOTE: prior to this fix, {"datasync","location"} had no arnToTF entry at
// all, so EVERY DataSync location -- s3 included, despite
// hydrateDataSyncLocationS3 already existing and being correctly
// registered -- silently fell into "Unmapped" regardless. That's the real
// bug this dispatcher closes, not just the 3 new location types.
func hydrateDataSyncLocation(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	cl := datasync.NewFromConfig(c.Cfg(r.Region))
	uri := ""
	token := (*string)(nil)
	for {
		page, err := cl.ListLocations(ctx, &datasync.ListLocationsInput{NextToken: token})
		if err != nil {
			return nil, err
		}
		for _, l := range page.Locations {
			if aws.ToString(l.LocationArn) == r.ARN {
				uri = aws.ToString(l.LocationUri)
				break
			}
		}
		if uri != "" || page.NextToken == nil {
			break
		}
		token = page.NextToken
	}
	scheme, _, ok := datasyncSplitURI(uri)
	if !ok {
		return nil, fmt.Errorf("could not determine DataSync location type from URI %q", uri)
	}

	switch scheme {
	case "s3":
		cfg, err := hydrateDataSyncLocationS3(ctx, c, r)
		if err != nil {
			return nil, err
		}
		cfg[retypeSentinel] = "aws_datasync_location_s3"
		return cfg, nil
	case "nfs":
		cfg, err := hydrateDataSyncLocationNFS(ctx, c, r)
		if err != nil {
			return nil, err
		}
		cfg[retypeSentinel] = "aws_datasync_location_nfs"
		return cfg, nil
	case "efs":
		cfg, err := hydrateDataSyncLocationEFS(ctx, c, r)
		if err != nil {
			return nil, err
		}
		cfg[retypeSentinel] = "aws_datasync_location_efs"
		return cfg, nil
	case "smb":
		// Required schema attribute "password" has no Read equivalent at
		// all -- confirmed against the real provider source, Read never
		// sets it. Unlike aws_ssm_parameter's SecureString (a deliberate
		// placeholder for a value that could, in principle, be decrypted
		// given permission), a password placeholder here would be a real,
		// live mutation risk: an `apply` would silently overwrite a real
		// SMB share's actual credential with the placeholder, breaking
		// connectivity. Same "genuinely can't be emitted" category as
		// aws_lb_trust_store -- not attempted.
		return nil, fmt.Errorf("aws_datasync_location_smb: password has no Read equivalent, not emittable")
	default:
		// hdfs, fsx*, azure-blob, object-storage: not yet supported.
		// Falling into this default is no worse than today's status quo
		// (every location type currently lands in Unmapped) -- only s3/
		// nfs/efs are confirmed handled by this dispatcher so far.
		return nil, fmt.Errorf("DataSync location type %q not yet supported", scheme)
	}
}

// datasyncSplitURI splits a DataSync LocationUri ("TYPE://GLOBAL_ID/SUBDIR")
// into its scheme and the remainder (GLOBAL_ID/SUBDIR), matching the real
// provider's own uri.go parsing (the general case; the S3-Outposts-access-
// point ARN branch it also handles isn't replicated here, same scope limit
// already noted on datasyncS3BucketARNAndSubdir).
func datasyncSplitURI(uri string) (scheme, rest string, ok bool) {
	i := strings.Index(uri, "://")
	if i <= 0 {
		return "", "", false
	}
	return uri[:i], uri[i+3:], true
}

// datasyncGlobalIDAndSubdir splits "GLOBAL_ID/SUBDIR" (the part of a
// LocationUri after "scheme://") at its first "/".
func datasyncGlobalIDAndSubdir(rest string) (globalID, subdir string, ok bool) {
	i := strings.IndexByte(rest, '/')
	if i <= 0 {
		return "", "", false
	}
	return rest[:i], rest[i:], true
}

func hydrateDataSyncLocationNFS(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	arn := r.ARN
	out, err := datasync.NewFromConfig(c.Cfg(r.Region)).DescribeLocationNfs(ctx, &datasync.DescribeLocationNfsInput{LocationArn: &arn})
	if err != nil {
		return nil, err
	}
	cfg := map[string]any{}
	if _, rest, ok := datasyncSplitURI(aws.ToString(out.LocationUri)); ok {
		if host, subdir, ok := datasyncGlobalIDAndSubdir(rest); ok {
			cfg["server_hostname"] = host
			cfg["subdirectory"] = subdir
		}
	}
	if out.OnPremConfig != nil && len(out.OnPremConfig.AgentArns) > 0 {
		cfg["on_prem_config"] = []any{map[string]any{"agent_arns": toAny(out.OnPremConfig.AgentArns)}}
	}
	if out.MountOptions != nil && string(out.MountOptions.Version) != "" {
		cfg["mount_options"] = []any{map[string]any{"version": string(out.MountOptions.Version)}}
	}
	return cfg, nil
}

func hydrateDataSyncLocationEFS(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	arn := r.ARN
	out, err := datasync.NewFromConfig(c.Cfg(r.Region)).DescribeLocationEfs(ctx, &datasync.DescribeLocationEfsInput{LocationArn: &arn})
	if err != nil {
		return nil, err
	}
	cfg := map[string]any{}
	// efs_file_system_arn is Required but never returned directly --
	// reconstructed from the URI's global id ("<region>.<fs-id>"), same
	// recipe as the real provider source (globalIDFromLocationURI +
	// building elasticfilesystem:...:file-system/<fs-id> by hand).
	if _, rest, ok := datasyncSplitURI(aws.ToString(out.LocationUri)); ok {
		if globalID, subdir, ok := datasyncGlobalIDAndSubdir(rest); ok {
			if subdir != "" {
				cfg["subdirectory"] = subdir
			}
			if region, fsID, ok := strings.Cut(globalID, "."); ok {
				if partition, _, _, account, _, pok := model.ParseARN(r.ARN); pok {
					cfg["efs_file_system_arn"] = "arn:" + partition + ":elasticfilesystem:" + region + ":" + account + ":file-system/" + fsID
				}
			}
		}
	}
	if out.Ec2Config != nil {
		ec2 := map[string]any{"security_group_arns": toAny(out.Ec2Config.SecurityGroupArns)}
		if v := aws.ToString(out.Ec2Config.SubnetArn); v != "" {
			ec2["subnet_arn"] = v
		}
		cfg["ec2_config"] = []any{ec2}
	}
	if v := aws.ToString(out.AccessPointArn); v != "" {
		cfg["access_point_arn"] = v
	}
	if v := aws.ToString(out.FileSystemAccessRoleArn); v != "" {
		cfg["file_system_access_role_arn"] = v
	}
	if v := string(out.InTransitEncryption); v != "" {
		cfg["in_transit_encryption"] = v
	}
	return cfg, nil
}
