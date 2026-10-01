package cspm

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// AWS holds SDK clients for the services the rules inspect.
type AWS struct {
	cfg        aws.Config
	S3         *s3.Client
	IAM        *iam.Client
	EC2        *ec2.Client
	CloudTrail *cloudtrail.Client
}

// NewAWS loads AWS configuration and builds the clients used by CSPM rules.
func NewAWS(ctx context.Context, region string, options ...func(*awsconfig.LoadOptions) error) (*AWS, error) {
	options = append([]func(*awsconfig.LoadOptions) error{awsconfig.WithRegion(region)}, options...)
	cfg, err := awsconfig.LoadDefaultConfig(ctx, options...)
	if err != nil {
		return nil, err
	}
	return &AWS{
		cfg:        cfg,
		S3:         s3.NewFromConfig(cfg),
		IAM:        iam.NewFromConfig(cfg),
		EC2:        ec2.NewFromConfig(cfg),
		CloudTrail: cloudtrail.NewFromConfig(cfg),
	}, nil
}

// DefaultRules registers the baseline CSPM rule set.
func DefaultRules() *Registry {
	r := NewRegistry()
	r.Register(publicS3BucketRule)
	r.Register(s3NoPublicAccessBlockRule)
	r.Register(s3VersioningDisabledRule)
	r.Register(s3LoggingDisabledRule)
	r.Register(iamUserNoMFARule)
	r.Register(rootAccessKeyRule)
	r.Register(rootNoMFARule)
	r.Register(accessKeyNotRotatedRule)
	r.Register(unusedAccessKeyRule)
	r.Register(openSecurityGroupRule)
	r.Register(ebsVolumeNotEncryptedRule)
	r.Register(cloudTrailNotEnabledRule)
	return r
}
