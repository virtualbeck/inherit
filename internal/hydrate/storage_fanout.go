package hydrate

import (
	"context"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/efs"
	"github.com/virtualbeck/inherit/model"
)

func init() {
	registerFanout("aws_efs_file_system", fanoutEFSMountTargets)
}

func fanoutEFSMountTargets(ctx context.Context, c *Clients, parent model.Resource) ([]model.Resource, error) {
	cl := efs.NewFromConfig(c.Cfg(parent.Region))
	fs := parent.ID
	out, err := cl.DescribeMountTargets(ctx, &efs.DescribeMountTargetsInput{FileSystemId: &fs})
	if err != nil {
		return nil, err
	}
	var kids []model.Resource
	for _, m := range out.MountTargets {
		cfg := map[string]any{
			"file_system_id": fs,
			"subnet_id":      aws.ToString(m.SubnetId),
		}
		if v := aws.ToString(m.IpAddress); v != "" {
			cfg["ip_address"] = v
		}
		kids = append(kids, model.Resource{
			Service: "elasticfilesystem", Type: "mount-target", TFType: "aws_efs_mount_target",
			Region: parent.Region, Account: parent.Account,
			ID:     aws.ToString(m.MountTargetId),
			Config: cfg,
		})
	}

	if ap, err := cl.DescribeAccessPoints(ctx, &efs.DescribeAccessPointsInput{FileSystemId: &fs}); err == nil {
		for _, a := range ap.AccessPoints {
			cfg := map[string]any{"file_system_id": fs}
			if p := a.PosixUser; p != nil {
				pu := map[string]any{}
				if p.Uid != nil {
					pu["uid"] = *p.Uid
				}
				if p.Gid != nil {
					pu["gid"] = *p.Gid
				}
				if len(p.SecondaryGids) > 0 {
					var g []any
					for _, x := range p.SecondaryGids {
						g = append(g, x)
					}
					pu["secondary_gids"] = g
				}
				cfg["posix_user"] = pu
			}
			if rd := a.RootDirectory; rd != nil {
				r := map[string]any{}
				if v := aws.ToString(rd.Path); v != "" {
					r["path"] = v
				}
				if cp := rd.CreationInfo; cp != nil {
					r["creation_info"] = map[string]any{
						"owner_uid":   aws.ToInt64(cp.OwnerUid),
						"owner_gid":   aws.ToInt64(cp.OwnerGid),
						"permissions": aws.ToString(cp.Permissions),
					}
				}
				if len(r) > 0 {
					cfg["root_directory"] = r
				}
			}
			tags := map[string]string{}
			for _, t := range a.Tags {
				if k := aws.ToString(t.Key); k != "" && !strings.HasPrefix(k, "aws:") {
					tags[k] = aws.ToString(t.Value)
				}
			}
			if len(tags) > 0 {
				cfg["tags"] = tags
			}
			kids = append(kids, model.Resource{
				Service: "elasticfilesystem", Type: "access-point", TFType: "aws_efs_access_point",
				Region: parent.Region, Account: parent.Account,
				ID:     aws.ToString(a.AccessPointId),
				Tags:   tags,
				Config: cfg,
			})
		}
	}
	return kids, nil
}
