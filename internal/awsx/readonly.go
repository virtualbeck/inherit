package awsx

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	awsmiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	"github.com/aws/smithy-go/middleware"
)

// readVerb matches AWS operation names that only ever read. AWS is remarkably
// consistent here: an operation that starts with one of these does not create,
// modify or delete anything.
var readVerb = regexp.MustCompile(`^(Describe|List|Get|BatchGet|Select|Lookup|Scan|Search|Query|Head|Retrieve|Preview|Estimate|Simulate|Check)[A-Z]`)

// denyOverride blocks the handful of read-verb operations that still have a
// side effect on the account (they generate a report, rotate a token, etc.).
var denyOverride = map[string]bool{
	"GenerateCredentialReport":           true, // iam
	"GenerateOrganizationsAccessReport":  true,
	"GenerateServiceLastAccessedDetails": true,
	"GetFederationToken":                 true, // sts - issues creds
	"GetSessionToken":                    true, // sts - issues creds
}

// allowOverride permits read-only operations that don't start with a read verb.
var allowOverride = map[string]bool{
	"GetCallerIdentity": true, // sts
	"AssumeRole":        true, // sts - needed for cross-account read; still no mutation of the target
}

// ReadOnlyError is returned (never panics) when a non-read operation is about to
// be sent. The operation does not execute.
type ReadOnlyError struct {
	Service   string
	Operation string
}

func (e *ReadOnlyError) Error() string {
	return fmt.Sprintf("inherit refuses to call %s:%s, it is not a read-only operation", e.Service, e.Operation)
}

// isReadOnly reports whether an operation is safe to send.
func isReadOnly(op string) bool {
	if allowOverride[op] {
		return true
	}
	if denyOverride[op] {
		return false
	}
	return readVerb.MatchString(op)
}

// readOnlyGuard is an SDK API option: it inserts an Initialize-step middleware
// that fails any request whose operation is not read-only, before it is
// serialized or signed. Applied to every client built from the shared config.
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
