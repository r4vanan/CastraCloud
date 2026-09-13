package cspm

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
)

var ebsVolumeNotEncryptedRule = Rule{
	ID:           "CASTRA-EC2-002",
	Title:        "EBS volume is not encrypted",
	Severity:     SeverityHigh,
	ResourceType: "ebs_volume",
	Description:  "The EBS volume is stored unencrypted, risking data exposure if it is leaked or snapshotted.",
	Remediation:  "Enable encryption by default for the region and migrate the volume to an encrypted one.",
	Check: func(ctx context.Context, c *AWS) ([]Finding, error) {
		out, err := c.EC2.DescribeVolumes(ctx, &ec2.DescribeVolumesInput{})
		if err != nil {
			return nil, err
		}
		var findings []Finding
		for _, v := range out.Volumes {
			if aws.ToBool(v.Encrypted) {
				continue
			}
			region := azRegion(aws.ToString(v.AvailabilityZone))
			findings = append(findings, newFinding(
				"CASTRA-EC2-002", "EBS volume is not encrypted", SeverityHigh,
				"ebs_volume", aws.ToString(v.VolumeId), aws.ToString(v.VolumeId), region, nil))
		}
		return findings, nil
	},
}

// azRegion derives a region name from an availability zone (us-east-1a → us-east-1).
func azRegion(az string) string {
	if len(az) > 1 {
		return az[:len(az)-1]
	}
	return az
}
