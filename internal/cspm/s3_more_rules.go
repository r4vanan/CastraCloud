package cspm

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

var s3VersioningDisabledRule = Rule{
	ID:           "CASTRA-S3-003",
	Title:        "S3 bucket versioning is disabled",
	Severity:     SeverityMedium,
	ResourceType: "s3_bucket",
	Description:  "Versioning is not enabled, so object overwrites and deletions are unrecoverable.",
	Remediation:  "Enable versioning on the bucket to retain and restore prior object versions.",
	Check: func(ctx context.Context, c *AWS) ([]Finding, error) {
		out, err := c.S3.ListBuckets(ctx, &s3.ListBucketsInput{})
		if err != nil {
			return nil, err
		}
		var findings []Finding
		for _, b := range out.Buckets {
			name := aws.ToString(b.Name)
			v, err := c.S3.GetBucketVersioning(ctx, &s3.GetBucketVersioningInput{Bucket: aws.String(name)})
			if err != nil {
				continue
			}
			if v.Status != types.BucketVersioningStatusEnabled {
				findings = append(findings, newFinding(
					"CASTRA-S3-003", "S3 bucket versioning is disabled", SeverityMedium,
					"s3_bucket", name, name, "", nil))
			}
		}
		return findings, nil
	},
}

var s3LoggingDisabledRule = Rule{
	ID:           "CASTRA-S3-004",
	Title:        "S3 bucket server access logging is disabled",
	Severity:     SeverityLow,
	ResourceType: "s3_bucket",
	Description:  "Server access logging is not configured, reducing auditability of bucket access.",
	Remediation:  "Enable server access logging and target a dedicated logging bucket.",
	Check: func(ctx context.Context, c *AWS) ([]Finding, error) {
		out, err := c.S3.ListBuckets(ctx, &s3.ListBucketsInput{})
		if err != nil {
			return nil, err
		}
		var findings []Finding
		for _, b := range out.Buckets {
			name := aws.ToString(b.Name)
			l, err := c.S3.GetBucketLogging(ctx, &s3.GetBucketLoggingInput{Bucket: aws.String(name)})
			if err != nil {
				continue
			}
			if l.LoggingEnabled == nil {
				findings = append(findings, newFinding(
					"CASTRA-S3-004", "S3 bucket server access logging is disabled", SeverityLow,
					"s3_bucket", name, name, "", nil))
			}
		}
		return findings, nil
	},
}
