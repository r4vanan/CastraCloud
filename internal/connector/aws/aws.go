// Package aws implements the CastraCloud CSPM connector for Amazon Web
// Services using the default credential chain (read-only IAM role).
package aws

import (
	"context"

	"github.com/castracloud/castracloud/internal/connector"
	"github.com/castracloud/castracloud/internal/cspm"
)

// AWS is the CSPM connector for Amazon Web Services.
type AWS struct {
	client *cspm.AWS
}

// New builds an AWS connector from the default credential chain.
func New(ctx context.Context, cfg connector.Config) (connector.Connector, error) {
	client, err := cspm.NewAWS(ctx, cfg.Region)
	if err != nil {
		return nil, err
	}
	return &AWS{client: client}, nil
}

// Provider reports the provider name.
func (a *AWS) Provider() string { return "aws" }

// Scan discovers AWS assets and evaluates the baseline rule set, returning
// findings such as public S3 buckets, missing Block Public Access, IAM users
// without MFA, and open security groups.
func (a *AWS) Scan(ctx context.Context) ([]cspm.Finding, error) {
	return cspm.DefaultRules().Run(ctx, a.client)
}

func init() {
	connector.Register("aws", New)
}
