package cspm

import (
	"context"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

var publicS3BucketRule = Rule{
	ID:           "CASTRA-S3-001",
	Title:        "S3 bucket is publicly accessible",
	Severity:     SeverityCritical,
	ResourceType: "s3_bucket",
	Description:  "The bucket grants public read/write access via its policy or ACL, exposing data to the internet.",
	Remediation:  "Restrict the bucket policy, enable Block Public Access, and remove public ACLs.",
	Check: func(ctx context.Context, c *AWS) ([]Finding, error) {
		out, err := c.S3.ListBuckets(ctx, &s3.ListBucketsInput{})
		if err != nil {
			return nil, err
		}
		var findings []Finding
		for _, b := range out.Buckets {
			name := aws.ToString(b.Name)
			public, why, err := isBucketPublic(ctx, c, name)
			if err != nil {
				continue
			}
			if public {
				findings = append(findings, newFinding(
					"CASTRA-S3-001", "S3 bucket is publicly accessible", SeverityCritical,
					"s3_bucket", name, name, "", map[string]string{"reason": why}))
			}
		}
		return findings, nil
	},
}

var s3NoPublicAccessBlockRule = Rule{
	ID:           "CASTRA-S3-002",
	Title:        "S3 bucket missing Block Public Access",
	Severity:     SeverityHigh,
	ResourceType: "s3_bucket",
	Description:  "Block Public Access is not fully enabled, leaving the bucket at risk of unintended exposure.",
	Remediation:  "Enable Block Public Access with BlockPublicAcls and BlockPublicPolicy set to true.",
	Check: func(ctx context.Context, c *AWS) ([]Finding, error) {
		out, err := c.S3.ListBuckets(ctx, &s3.ListBucketsInput{})
		if err != nil {
			return nil, err
		}
		var findings []Finding
		for _, b := range out.Buckets {
			name := aws.ToString(b.Name)
			cfg, err := c.S3.GetPublicAccessBlock(ctx, &s3.GetPublicAccessBlockInput{Bucket: aws.String(name)})
			if err != nil {
				findings = append(findings, newFinding(
					"CASTRA-S3-002", "S3 bucket missing Block Public Access", SeverityHigh,
					"s3_bucket", name, name, "",
					map[string]string{"reason": "no public access block configured"}))
				continue
			}
			pab := cfg.PublicAccessBlockConfiguration
			if !aws.ToBool(pab.BlockPublicAcls) || !aws.ToBool(pab.BlockPublicPolicy) {
				findings = append(findings, newFinding(
					"CASTRA-S3-002", "S3 bucket missing Block Public Access", SeverityHigh,
					"s3_bucket", name, name, "",
					map[string]string{"reason": "block acls/policy not fully enabled"}))
			}
		}
		return findings, nil
	},
}

func isBucketPublic(ctx context.Context, c *AWS, name string) (bool, string, error) {
	pol, err := c.S3.GetBucketPolicy(ctx, &s3.GetBucketPolicyInput{Bucket: aws.String(name)})
	if err == nil && pol.Policy != nil && strings.Contains(*pol.Policy, `"Principal":"*"`) {
		return true, "bucket policy grants access to Principal *", nil
	}

	acl, err := c.S3.GetBucketAcl(ctx, &s3.GetBucketAclInput{Bucket: aws.String(name)})
	if err == nil {
		for _, g := range acl.Grants {
			if g.Grantee != nil && g.Grantee.URI != nil &&
				strings.Contains(*g.Grantee.URI, "AllUsers") {
				return true, "ACL grants access to AllUsers", nil
			}
		}
	}
	return false, "", nil
}

func newFinding(ruleID, title string, sev Severity, resType, id, name, region string, details map[string]string) Finding {
	return Finding{
		RuleID:       ruleID,
		Title:        title,
		Severity:     sev,
		Description:  title,
		Remediation:  "See CastraCloud remediation guidance for " + ruleID + ".",
		Provider:     "aws",
		ResourceType: resType,
		ResourceID:   id,
		ResourceName: name,
		Region:       region,
		Details:      details,
	}
}
