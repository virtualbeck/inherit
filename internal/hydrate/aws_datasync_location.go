package hydrate

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/datasync"
	"github.com/virtualbeck/inherit/model"
)

// Shared ARN segment; LocationUri decides the real type.
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
		// no Read for password; placeholders would overwrite
		return nil, fmt.Errorf("aws_datasync_location_smb: password has no Read equivalent, not emittable")
	default:
		// hdfs, fsx, azure-blob, object-storage: unsupported
		return nil, fmt.Errorf("DataSync location type %q not yet supported", scheme)
	}
}

// datasyncSplitURI splits TYPE://GLOBAL_ID/SUBDIR at the scheme.
func datasyncSplitURI(uri string) (scheme, rest string, ok bool) {
	i := strings.Index(uri, "://")
	if i <= 0 {
		return "", "", false
	}
	return uri[:i], uri[i+3:], true
}

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
	// rebuilt from the URI's <region>.<fs-id>
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
