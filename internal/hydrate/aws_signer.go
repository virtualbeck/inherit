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

// fetchSigningProfile's ProfileName doesn't snake-case to the schema's
// "name" (an override, not a Generic() nested-block issue).
func fetchSigningProfile(ctx context.Context, c *Clients, r model.Resource) (any, error) {
	name := r.ID
	out, err := signer.NewFromConfig(c.Cfg(r.Region)).GetSigningProfile(ctx, &signer.GetSigningProfileInput{ProfileName: &name})
	if err != nil {
		return nil, err
	}
	// A Canceled/Revoked profile still answers GetSigningProfile (list/tagging
	// discovery both still see it) but the provider's own Read treats it as
	// gone, so import always 404s -- same "discovered but not really there"
	// exclusion as INACTIVE ECS task definitions / PendingDeletion KMS keys.
	if out.Status != signertypes.SigningProfileStatusActive {
		return nil, fmt.Errorf("signing profile %q is %s, not Active", name, out.Status)
	}
	return out, nil
}
