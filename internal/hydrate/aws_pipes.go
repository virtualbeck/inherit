package hydrate

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/pipes"
	"github.com/virtualbeck/inherit/model"
)

func init() { register("aws_pipes_pipe", genericHydrator("aws_pipes_pipe", fetchPipe)) }

func fetchPipe(ctx context.Context, c *Clients, r model.Resource) (any, error) {
	name := r.ID
	out, err := pipes.NewFromConfig(c.Cfg(r.Region)).DescribePipe(ctx, &pipes.DescribePipeInput{Name: &name})
	if err != nil {
		return nil, err
	}
	return out, nil
}
