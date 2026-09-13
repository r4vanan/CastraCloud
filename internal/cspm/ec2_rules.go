package cspm

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
)

var openSecurityGroupRule = Rule{
	ID:           "CASTRA-EC2-001",
	Title:        "Security group open to the internet",
	Severity:     SeverityCritical,
	ResourceType: "security_group",
	Description:  "An ingress rule allows traffic from 0.0.0.0/0 on a sensitive port.",
	Remediation:  "Restrict the source CIDR to trusted ranges and reduce the open port range.",
	Check: func(ctx context.Context, c *AWS) ([]Finding, error) {
		out, err := c.EC2.DescribeSecurityGroups(ctx, &ec2.DescribeSecurityGroupsInput{})
		if err != nil {
			return nil, err
		}
		var findings []Finding
		for _, sg := range out.SecurityGroups {
			for _, perm := range sg.IpPermissions {
				for _, ipRange := range perm.IpRanges {
					if aws.ToString(ipRange.CidrIp) != "0.0.0.0/0" {
						continue
					}
					port := portRange(aws.ToInt32(perm.FromPort), aws.ToInt32(perm.ToPort))
					findings = append(findings, newFinding(
						"CASTRA-EC2-001", "Security group open to the internet", SeverityCritical,
						"security_group", aws.ToString(sg.GroupId), aws.ToString(sg.GroupName),
						aws.ToString(sg.GroupId), map[string]string{"port": port}))
				}
			}
		}
		return findings, nil
	},
}

func portRange(from, to int32) string {
	if from == to {
		return itoa(from)
	}
	return itoa(from) + "-" + itoa(to)
}

func itoa(n int32) string {
	if n == 0 {
		return "0"
	}
	var b [12]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
