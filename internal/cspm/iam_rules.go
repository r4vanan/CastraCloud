package cspm

import (
	"context"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
)

// maxAccessKeyAge is the threshold beyond which access keys are considered
// stale/unused.
const maxAccessKeyAge = 90 * 24 * time.Hour

var iamUserNoMFARule = Rule{
	ID:           "CASTRA-IAM-001",
	Title:        "IAM user without MFA",
	Severity:     SeverityHigh,
	ResourceType: "iam_user",
	Description:  "The IAM user has no MFA device, weakening protection against credential theft.",
	Remediation:  "Attach a virtual or hardware MFA device to the user, or enforce MFA via policy.",
	Check: func(ctx context.Context, c *AWS) ([]Finding, error) {
		out, err := c.IAM.ListUsers(ctx, &iam.ListUsersInput{})
		if err != nil {
			return nil, err
		}
		var findings []Finding
		for _, u := range out.Users {
			name := aws.ToString(u.UserName)
			mfa, err := c.IAM.ListMFADevices(ctx, &iam.ListMFADevicesInput{UserName: aws.String(name)})
			if err != nil {
				continue
			}
			if len(mfa.MFADevices) == 0 {
				findings = append(findings, newFinding(
					"CASTRA-IAM-001", "IAM user without MFA", SeverityHigh,
					"iam_user", name, name, "", nil))
			}
		}
		return findings, nil
	},
}

var rootAccessKeyRule = Rule{
	ID:           "CASTRA-IAM-002",
	Title:        "Root account has active access keys",
	Severity:     SeverityCritical,
	ResourceType: "aws_account",
	Description:  "The AWS root account has access keys, which bypass IAM policies and are a critical risk.",
	Remediation:  "Delete root access keys and use IAM roles or IAM users for programmatic access.",
	Check: func(ctx context.Context, c *AWS) ([]Finding, error) {
		sum, err := accountSummary(ctx, c)
		if err != nil {
			return nil, err
		}
		if sum["AccountAccessKeysPresent"] > 0 {
			return []Finding{newFinding(
				"CASTRA-IAM-002", "Root account has active access keys", SeverityCritical,
				"aws_account", "root", "root", "", nil)}, nil
		}
		return nil, nil
	},
}

var rootNoMFARule = Rule{
	ID:           "CASTRA-IAM-003",
	Title:        "Root account has no MFA enabled",
	Severity:     SeverityCritical,
	ResourceType: "aws_account",
	Description:  "The AWS root account does not have MFA enabled, exposing the account to takeover.",
	Remediation:  "Enable a hardware or virtual MFA device on the root account.",
	Check: func(ctx context.Context, c *AWS) ([]Finding, error) {
		sum, err := accountSummary(ctx, c)
		if err != nil {
			return nil, err
		}
		if sum["AccountMFAEnabled"] == 0 {
			return []Finding{newFinding(
				"CASTRA-IAM-003", "Root account has no MFA enabled", SeverityCritical,
				"aws_account", "root", "root", "", nil)}, nil
		}
		return nil, nil
	},
}

var accessKeyNotRotatedRule = Rule{
	ID:           "CASTRA-IAM-004",
	Title:        "IAM access key has not been rotated in 90 days",
	Severity:     SeverityMedium,
	ResourceType: "iam_user",
	Description:  "The active access key is older than 90 days, increasing exposure to leaked credentials.",
	Remediation:  "Rotate the access key and enforce a rotation schedule via policy or automation.",
	Check: func(ctx context.Context, c *AWS) ([]Finding, error) {
		out, err := c.IAM.ListUsers(ctx, &iam.ListUsersInput{})
		if err != nil {
			return nil, err
		}
		var findings []Finding
		for _, u := range out.Users {
			userName := aws.ToString(u.UserName)
			keys, err := c.IAM.ListAccessKeys(ctx, &iam.ListAccessKeysInput{UserName: aws.String(userName)})
			if err != nil {
				continue
			}
			for _, k := range keys.AccessKeyMetadata {
				if k.Status != types.StatusTypeActive || k.CreateDate == nil {
					continue
				}
				if time.Since(*k.CreateDate) > maxAccessKeyAge {
					findings = append(findings, newFinding(
						"CASTRA-IAM-004", "IAM access key has not been rotated in 90 days", SeverityMedium,
						"iam_user", userName, userName, "",
						map[string]string{"access_key": aws.ToString(k.AccessKeyId)}))
				}
			}
		}
		return findings, nil
	},
}

var unusedAccessKeyRule = Rule{
	ID:           "CASTRA-IAM-005",
	Title:        "IAM access key has not been used in 90 days",
	Severity:     SeverityLow,
	ResourceType: "iam_user",
	Description:  "The active access key has not been used recently and should be removed to reduce attack surface.",
	Remediation:  "Remove unused access keys, or rotate and track their use via CloudTrail.",
	Check: func(ctx context.Context, c *AWS) ([]Finding, error) {
		out, err := c.IAM.ListUsers(ctx, &iam.ListUsersInput{})
		if err != nil {
			return nil, err
		}
		var findings []Finding
		for _, u := range out.Users {
			userName := aws.ToString(u.UserName)
			keys, err := c.IAM.ListAccessKeys(ctx, &iam.ListAccessKeysInput{UserName: aws.String(userName)})
			if err != nil {
				continue
			}
			for _, k := range keys.AccessKeyMetadata {
				if k.Status != types.StatusTypeActive {
					continue
				}
				last, err := c.IAM.GetAccessKeyLastUsed(ctx, &iam.GetAccessKeyLastUsedInput{AccessKeyId: k.AccessKeyId})
				if err != nil {
					continue
				}
				unused := true
				if last.AccessKeyLastUsed != nil && last.AccessKeyLastUsed.LastUsedDate != nil {
					unused = time.Since(*last.AccessKeyLastUsed.LastUsedDate) > maxAccessKeyAge
				}
				if unused {
					findings = append(findings, newFinding(
						"CASTRA-IAM-005", "IAM access key has not been used in 90 days", SeverityLow,
						"iam_user", userName, userName, "",
						map[string]string{"access_key": aws.ToString(k.AccessKeyId)}))
				}
			}
		}
		return findings, nil
	},
}

// accountSummary returns the IAM account summary map (root MFA, access keys, etc.).
func accountSummary(ctx context.Context, c *AWS) (map[string]int32, error) {
	out, err := c.IAM.GetAccountSummary(ctx, &iam.GetAccountSummaryInput{})
	if err != nil {
		return nil, err
	}
	return out.SummaryMap, nil
}
