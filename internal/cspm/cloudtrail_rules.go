package cspm

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
)

var cloudTrailNotEnabledRule = Rule{
	ID:           "CASTRA-CT-001",
	Title:        "CloudTrail multi-region trail is not enabled",
	Severity:     SeverityHigh,
	ResourceType: "cloudtrail",
	Description:  "No multi-region CloudTrail trail is enabled, so API activity may not be logged across regions.",
	Remediation:  "Create a CloudTrail trail with IsMultiRegionTrail enabled and a dedicated S3 bucket.",
	Check: func(ctx context.Context, c *AWS) ([]Finding, error) {
		out, err := c.CloudTrail.DescribeTrails(ctx, &cloudtrail.DescribeTrailsInput{})
		if err != nil {
			return nil, err
		}
		for _, t := range out.TrailList {
			if aws.ToBool(t.IsMultiRegionTrail) {
				return nil, nil
			}
		}
		return []Finding{newFinding(
			"CASTRA-CT-001", "CloudTrail multi-region trail is not enabled", SeverityHigh,
			"cloudtrail", "account", "account", "", nil)}, nil
	},
}
