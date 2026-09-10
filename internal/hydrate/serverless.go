package hydrate

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	agw "github.com/aws/aws-sdk-go-v2/service/apigateway"
	agw2 "github.com/aws/aws-sdk-go-v2/service/apigatewayv2"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/virtualbeck/inherit-core/model"
)

func init() {
	register("aws_lambda_function", hydrateLambdaFunction)
	register("aws_lambda_layer_version", hydrateLambdaLayerVersion)
	register("aws_api_gateway_rest_api", genericHydrator("aws_api_gateway_rest_api", fetchRestAPI))
	register("aws_apigatewayv2_api", genericHydrator("aws_apigatewayv2_api", fetchAPIv2))
}

func hydrateLambdaFunction(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	sch, err := schemaFor("aws_lambda_function")
	if err != nil {
		return nil, err
	}
	name := r.ID
	out, err := lambda.NewFromConfig(c.Cfg(r.Region)).GetFunction(ctx, &lambda.GetFunctionInput{FunctionName: &name})
	if err != nil {
		return nil, err
	}
	// Configuration holds the settable knobs; Code is a URL we can't reproduce.
	cfg, err := Generic(out.Configuration, sch, nil)
	if err != nil {
		return nil, err
	}
	// The provider requires a code source (filename / s3_bucket / image_uri).
	// For container images we have the URI; for zip packages the deployment
	// artifact is not recoverable, so emit.Write drops in a placeholder.
	if string(out.Configuration.PackageType) == "Image" {
		cfg["package_type"] = "Image"
		delete(cfg, "runtime")
		delete(cfg, "handler")
		if out.Code != nil && aws.ToString(out.Code.ImageUri) != "" {
			cfg["image_uri"] = aws.ToString(out.Code.ImageUri)
		}
	}
	// publish is a provider-side directive (whether apply should publish a new
	// version), not a real attribute of GetFunction; AWS has no notion of it.
	// Pin it to the provider default so the plan doesn't offer to "add" it.
	cfg["publish"] = false
	// layers is list(string) of layer ARNs in the schema, but
	// Configuration.Layers is []Layer{Arn, CodeSize, ...} -- Generic() has no
	// way to know to project down to just Arn, so it passed the raw objects
	// through untouched. Any function with a layer attached (very common:
	// observability agents, shared deps) would emit a list of objects where
	// the provider expects strings.
	if len(out.Configuration.Layers) > 0 {
		layers := make([]any, len(out.Configuration.Layers))
		for i, l := range out.Configuration.Layers {
			layers[i] = aws.ToString(l.Arn)
		}
		cfg["layers"] = layers
	} else {
		delete(cfg, "layers")
	}
	// Generic() drops snap_start when Configuration.SnapStart is nil (container
	// images, and some older/unsupported runtimes never populate it). AWS
	// still accepts the no-op default explicitly, so fall back to it rather
	// than omitting the block.
	if _, ok := cfg["snap_start"]; !ok {
		applyOn := "None"
		if out.Configuration.SnapStart != nil {
			applyOn = string(out.Configuration.SnapStart.ApplyOn)
		}
		cfg["snap_start"] = []any{map[string]any{"apply_on": applyOn}}
	}
	return cfg, nil
}

func hydrateLambdaLayerVersion(ctx context.Context, c *Clients, r model.Resource) (map[string]any, error) {
	// r.ID for "arn:aws:lambda:region:acct:layer:my-layer:3" is "my-layer:3"
	layerName, verStr, ok := strings.Cut(r.ID, ":")
	if !ok {
		return nil, fmt.Errorf("unexpected layer id %q", r.ID)
	}
	ver, err := strconv.ParseInt(verStr, 10, 64)
	if err != nil {
		return nil, err
	}
	out, err := lambda.NewFromConfig(c.Cfg(r.Region)).GetLayerVersion(ctx, &lambda.GetLayerVersionInput{
		LayerName: &layerName, VersionNumber: &ver,
	})
	if err != nil {
		return nil, err
	}
	cfg := map[string]any{"layer_name": layerName}
	if v := aws.ToString(out.Description); v != "" {
		cfg["description"] = v
	}
	if len(out.CompatibleRuntimes) > 0 {
		var rt []any
		for _, x := range out.CompatibleRuntimes {
			rt = append(rt, string(x))
		}
		cfg["compatible_runtimes"] = rt
	}
	if len(out.CompatibleArchitectures) > 0 {
		var a []any
		for _, x := range out.CompatibleArchitectures {
			a = append(a, string(x))
		}
		cfg["compatible_architectures"] = a
	}
	if v := aws.ToString(out.LicenseInfo); v != "" {
		cfg["license_info"] = v
	}
	// the layer payload itself is not recoverable; emit.Write drops in a placeholder
	return cfg, nil
}

func fetchRestAPI(ctx context.Context, c *Clients, r model.Resource) (any, error) {
	out, err := agw.NewFromConfig(c.Cfg(r.Region)).GetRestApi(ctx, &agw.GetRestApiInput{RestApiId: &r.ID})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func fetchAPIv2(ctx context.Context, c *Clients, r model.Resource) (any, error) {
	out, err := agw2.NewFromConfig(c.Cfg(r.Region)).GetApi(ctx, &agw2.GetApiInput{ApiId: &r.ID})
	if err != nil {
		return nil, err
	}
	return out, nil
}
