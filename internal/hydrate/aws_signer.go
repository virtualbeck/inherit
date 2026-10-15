package hydrate

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/signer"
	signertypes "github.com/aws/aws-sdk-go-v2/service/signer/types"
	"github.com/virtualbeck/inherit/model"
)

func init() {
	register("aws_signer_signing_profile", genericHydratorOverride(
		"aws_signer_signing_profile", fetchSigningProfile, map[string]string{"profile_name": "name"},
	))
}

// ProfileName maps to name.
func fetchSigningProfile(ctx context.Context, c *Clients, r model.Resource) (any, error) {
	name := r.ID
	out, err := signer.NewFromConfig(c.Cfg(r.Region)).GetSigningProfile(ctx, &signer.GetSigningProfileInput{ProfileName: &name})
	if err != nil {
		return nil, err
	}
	// inactive profiles can't be imported
	if out.Status != signertypes.SigningProfileStatusActive {
		return nil, fmt.Errorf("signing profile %q is %s, not Active", name, out.Status)
	}
	return out, nil
}
