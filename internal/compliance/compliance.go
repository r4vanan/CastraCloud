// Package compliance seeds standard frameworks (CIS, NIST CSF, ISO 27001) and
// maps detection rules to their controls.
package compliance

import (
	"context"

	"github.com/castracloud/castracloud/internal/store"
	"github.com/google/uuid"
)

// ControlDef is a control definition within a framework.
type ControlDef struct {
	ID          string
	Title       string
	Description string
}

// FrameworkDef is a compliance framework definition.
type FrameworkDef struct {
	Name     string
	Version  string
	Controls []ControlDef
}

// Frameworks is the built-in framework catalog.
var Frameworks = []FrameworkDef{
	{
		Name: "CIS AWS Foundations Benchmark", Version: "2.0.0",
		Controls: []ControlDef{
			{"1.4", "Ensure no root user account access key exists", "The root account must not have programmatic access keys."},
			{"1.5", "Ensure MFA is enabled for the root user", "The root account must be protected by MFA."},
			{"1.10", "Ensure IAM users receive MFA", "All IAM users should have an MFA device."},
			{"1.14", "Ensure access keys are rotated every 90 days or less", "Active access keys should be rotated on schedule."},
			{"2.1.2", "Ensure S3 Block Public Access is enabled", "Bucket-level block public access should be on."},
			{"2.1.4", "Ensure S3 bucket versioning is enabled", "Versioning protects against data loss."},
			{"2.1.5", "Ensure S3 buckets are not publicly accessible", "Buckets must not expose data to the internet."},
			{"2.3.1", "Ensure EBS volumes are encrypted", "EBS volumes should be encrypted at rest."},
			{"3.1", "Ensure CloudTrail is enabled in all regions", "A multi-region trail must exist."},
			{"5.2", "Ensure no security groups allow ingress from 0.0.0.0/0", "Security groups must not be open to the internet."},
		},
	},
	{
		Name: "NIST CSF", Version: "2.0",
		Controls: []ControlDef{
			{"PR.AC-1", "Identities and credentials are managed", "Manage identity and credentials."},
			{"PR.DS-1", "Data at rest is protected", "Protect stored data."},
			{"PR.DS-5", "Protections against data leaks are implemented", "Prevent data leakage."},
			{"PR.PT-1", "Communications and control networks are protected", "Boundary protection."},
			{"DE.CM-1", "The network is monitored to detect cybersecurity events", "Continuous monitoring."},
			{"RS.MI-2", "Incidents are mitigated", "Response and mitigation."},
		},
	},
	{
		Name: "ISO 27001", Version: "2022",
		Controls: []ControlDef{
			{"A.5.15", "Access control", "Rules to control physical and logical access."},
			{"A.5.16", "Identity management", "Manage the full identity life cycle."},
			{"A.8.1", "User endpoint devices", "Protect information on endpoint devices."},
			{"A.8.12", "Data leakage prevention", "Prevent unauthorized disclosure of data."},
			{"A.8.15", "Logging", "Record events and generate evidence."},
			{"A.8.20", "Networks security", "Protect networks and their services."},
			{"A.8.24", "Use of cryptography", "Define and implement cryptographic controls."},
		},
	},
}

// ruleControls maps detection rule IDs to (framework, control) references.
var ruleControls = map[string][][2]string{
	"CASTRA-S3-001":   {{"CIS AWS Foundations Benchmark", "2.1.5"}, {"NIST CSF", "PR.DS-5"}, {"ISO 27001", "A.8.12"}},
	"CASTRA-S3-002":   {{"CIS AWS Foundations Benchmark", "2.1.2"}, {"NIST CSF", "PR.DS-5"}, {"ISO 27001", "A.8.12"}},
	"CASTRA-S3-003":   {{"CIS AWS Foundations Benchmark", "2.1.4"}, {"NIST CSF", "PR.DS-1"}},
	"CASTRA-S3-004":   {{"NIST CSF", "DE.CM-1"}, {"ISO 27001", "A.8.15"}},
	"CASTRA-IAM-001":  {{"CIS AWS Foundations Benchmark", "1.10"}, {"NIST CSF", "PR.AC-1"}, {"ISO 27001", "A.5.16"}},
	"CASTRA-IAM-002":  {{"CIS AWS Foundations Benchmark", "1.4"}, {"NIST CSF", "PR.AC-1"}},
	"CASTRA-IAM-003":  {{"CIS AWS Foundations Benchmark", "1.5"}, {"NIST CSF", "PR.AC-1"}, {"ISO 27001", "A.5.15"}},
	"CASTRA-IAM-004":  {{"CIS AWS Foundations Benchmark", "1.14"}, {"NIST CSF", "PR.AC-1"}},
	"CASTRA-IAM-005":  {{"NIST CSF", "PR.AC-1"}},
	"CASTRA-EC2-001":  {{"CIS AWS Foundations Benchmark", "5.2"}, {"NIST CSF", "PR.PT-1"}, {"ISO 27001", "A.8.20"}},
	"CASTRA-EC2-002":  {{"CIS AWS Foundations Benchmark", "2.3.1"}, {"NIST CSF", "PR.DS-1"}, {"ISO 27001", "A.8.24"}},
	"CASTRA-CT-001":   {{"CIS AWS Foundations Benchmark", "3.1"}, {"NIST CSF", "DE.CM-1"}},
	"CASTRA-GCP-001":  {{"NIST CSF", "PR.DS-5"}, {"ISO 27001", "A.8.12"}},
	"CASTRA-GCP-002":  {{"NIST CSF", "PR.PT-1"}, {"ISO 27001", "A.8.20"}},
	"CASTRA-AZURE-001": {{"NIST CSF", "PR.PT-1"}, {"ISO 27001", "A.8.20"}},
	"CASTRA-AZURE-002": {{"NIST CSF", "PR.DS-5"}, {"ISO 27001", "A.8.12"}},
	"CASTRA-DOM-001":  {{"NIST CSF", "PR.DS-5"}},
	"CASTRA-DOM-002":  {{"NIST CSF", "PR.DS-1"}},
	"CASTRA-DOM-003":  {{"NIST CSF", "PR.DS-5"}, {"ISO 27001", "A.5.15"}},
	"CASTRA-DOM-004":  {{"NIST CSF", "DE.CM-1"}},
}

// Seed idempotently upserts the framework catalog and rule mappings for a
// tenant. Safe to call on every compliance access.
func Seed(ctx context.Context, db *store.DB, tenantID uuid.UUID) error {
	controlByKey := map[string]uuid.UUID{}
	for _, fw := range Frameworks {
		f, err := db.UpsertFramework(ctx, tenantID, fw.Name, fw.Version)
		if err != nil {
			return err
		}
		for _, c := range fw.Controls {
			ctrl, err := db.UpsertControl(ctx, f.ID, c.ID, c.Title, c.Description)
			if err != nil {
				return err
			}
			controlByKey[fw.Name+"|"+c.ID] = ctrl.ID
		}
	}

	for rule, refs := range ruleControls {
		for _, ref := range refs {
			ctrlID, ok := controlByKey[ref[0]+"|"+ref[1]]
			if !ok {
				continue
			}
			if err := db.MapRuleControl(ctx, rule, ctrlID); err != nil {
				return err
			}
		}
	}
	return nil
}
