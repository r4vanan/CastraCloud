// Package aws implements the CastraCloud CSPM connector for Amazon Web
// Services using the default credential chain (read-only IAM role).
package aws

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/castracloud/castracloud/internal/connector"
	"github.com/castracloud/castracloud/internal/cspm"
)

// AWS is the CSPM connector for Amazon Web Services.
type AWS struct {
	client *cspm.AWS
}

// New builds an AWS connector from the configured credentials or the default
// credential chain when the integration uses workload identity.
func New(ctx context.Context, cfg connector.Config) (connector.Connector, error) {
	options := make([]func(*awsconfig.LoadOptions) error, 0, 1)
	if strings.TrimSpace(cfg.Credentials) != "" {
		var creds struct {
			AccessKeyID     string `json:"access_key_id"`
			SecretAccessKey string `json:"secret_access_key"`
			SessionToken    string `json:"session_token"`
		}
		if err := json.Unmarshal([]byte(cfg.Credentials), &creds); err != nil {
			return nil, err
		}
		if creds.AccessKeyID == "" || creds.SecretAccessKey == "" {
			return nil, errors.New("aws connector credentials require access_key_id and secret_access_key")
		}
		options = append(options, awsconfig.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(creds.AccessKeyID, creds.SecretAccessKey, creds.SessionToken),
		))
	}
	client, err := cspm.NewAWS(ctx, cfg.Region, options...)
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
