package awsx

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	awsmiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	"github.com/aws/smithy-go/middleware"
)

// Operation names that only ever read.
var readVerb = regexp.MustCompile(`^(Describe|List|Get|BatchGet|Select|Lookup|Scan|Search|Query|Head|Retrieve|Preview|Estimate|Simulate|Check)[A-Z]`)

// Read verbs that still have side effects.
var denyOverride = map[string]bool{
	"GenerateCredentialReport":           true,
	"GenerateOrganizationsAccessReport":  true,
	"GenerateServiceLastAccessedDetails": true,
	"GetFederationToken":                 true, // sts - issues creds
	"GetSessionToken":                    true, // sts - issues creds
}

// Read-only operations without a read verb.
var allowOverride = map[string]bool{
	"GetCallerIdentity": true,
	"AssumeRole":        true, // cross-account read; never mutates the target
}

// ReadOnlyError rejects a non-read operation before sending.
type ReadOnlyError struct {
	Service   string
	Operation string
}

func (e *ReadOnlyError) Error() string {
	return fmt.Sprintf("inherit refuses to call %s:%s, it is not a read-only operation", e.Service, e.Operation)
}

func isReadOnly(op string) bool {
	if allowOverride[op] {
		return true
	}
	if denyOverride[op] {
		return false
	}
	return readVerb.MatchString(op)
}

// readOnlyGuard fails non-read requests before signing.
func readOnlyGuard(stack *middleware.Stack) error {
	return stack.Initialize.Add(
		middleware.InitializeMiddlewareFunc("inherit:ReadOnlyGuard", func(
			ctx context.Context, in middleware.InitializeInput, next middleware.InitializeHandler,
		) (middleware.InitializeOutput, middleware.Metadata, error) {
			op := awsmiddleware.GetOperationName(ctx)
			svc := awsmiddleware.GetServiceID(ctx)
			if op != "" && !isReadOnly(op) {
				return middleware.InitializeOutput{}, middleware.Metadata{}, &ReadOnlyError{
					Service:   strings.ToLower(svc),
					Operation: op,
				}
			}
			return next.HandleInitialize(ctx, in)
		}),
		middleware.Before,
	)
}
