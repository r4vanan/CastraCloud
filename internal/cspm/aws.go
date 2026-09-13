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

// NewAWS loads AWS credentials from the environment/chain and builds clients.
func NewAWS(ctx context.Context, region string) (*AWS, error) {
	cfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region))
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
