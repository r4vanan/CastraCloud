// Package azure implements the CastraCloud CSPM connector for Microsoft Azure
// using DefaultAzureCredential (managed identity or service principal).
package azure

import (
	"context"
	"errors"
	"os"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v2"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage"

	"github.com/castracloud/castracloud/internal/connector"
	"github.com/castracloud/castracloud/internal/cspm"
)

// Azure is the CSPM connector for Microsoft Azure.
type Azure struct {
	nsg      *armnetwork.SecurityGroupsClient
	accounts *armstorage.AccountsClient
}

// New builds an Azure connector from DefaultAzureCredential. The subscription
// is read from AZURE_SUBSCRIPTION_ID.
func New(ctx context.Context, cfg connector.Config) (connector.Connector, error) {
	sub := os.Getenv("AZURE_SUBSCRIPTION_ID")
	if sub == "" {
		return nil, errors.New("AZURE_SUBSCRIPTION_ID is required")
	}
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, err
	}
	nsg, err := armnetwork.NewSecurityGroupsClient(sub, cred, nil)
	if err != nil {
		return nil, err
	}
	accounts, err := armstorage.NewAccountsClient(sub, cred, nil)
	if err != nil {
		return nil, err
	}
	return &Azure{nsg: nsg, accounts: accounts}, nil
}

// Provider reports the provider name.
func (a *Azure) Provider() string { return "azure" }

// Scan evaluates the Azure baseline rule set and returns the findings.
func (a *Azure) Scan(ctx context.Context) ([]cspm.Finding, error) {
	var all []cspm.Finding

	nsgs, err := a.openNSGs(ctx)
	if err != nil {
		return nil, err
	}
	all = append(all, nsgs...)

	blobs, err := a.publicBlobAccounts(ctx)
	if err != nil {
		return nil, err
	}
	all = append(all, blobs...)

	return all, nil
}

func (a *Azure) openNSGs(ctx context.Context) ([]cspm.Finding, error) {
	pager := a.nsg.NewListAllPager(nil)
	var findings []cspm.Finding
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, sg := range page.Value {
			if sg.Properties == nil {
				continue
			}
			var ports []string
			for _, rule := range sg.Properties.SecurityRules {
				if rule.Properties == nil {
					continue
				}
				p := rule.Properties
				if p.Direction != nil && *p.Direction != armnetwork.SecurityRuleDirectionInbound {
					continue
				}
				if p.Access != nil && *p.Access != armnetwork.SecurityRuleAccessAllow {
					continue
				}
				if isOpenSource(p) {
					ports = append(ports, rulePort(p))
				}
			}
			if len(ports) > 0 {
				name := strPtr(sg.Name)
				findings = append(findings, newFinding(
					"CASTRA-AZURE-001", "Network security group allows traffic from the internet", cspm.SeverityHigh,
					"network_security_group", name, name, "",
					map[string]string{"rules": strings.Join(ports, "; ")}))
			}
		}
	}
	return findings, nil
}

func (a *Azure) publicBlobAccounts(ctx context.Context) ([]cspm.Finding, error) {
	pager := a.accounts.NewListPager(nil)
	var findings []cspm.Finding
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, acct := range page.Value {
			if acct.Properties == nil {
				continue
			}
			if acct.Properties.AllowBlobPublicAccess == nil || *acct.Properties.AllowBlobPublicAccess {
				name := strPtr(acct.Name)
				findings = append(findings, newFinding(
					"CASTRA-AZURE-002", "Storage account allows public blob access", cspm.SeverityHigh,
					"storage_account", name, name, "", nil))
			}
		}
	}
	return findings, nil
}

func isOpenSource(p *armnetwork.SecurityRulePropertiesFormat) bool {
	if open := openPrefix(p.SourceAddressPrefix); open {
		return true
	}
	for _, sp := range p.SourceAddressPrefixes {
		if open := openPrefix(sp); open {
			return true
		}
	}
	return false
}

func openPrefix(v *string) bool {
	if v == nil {
		return false
	}
	s := strings.ToLower(*v)
	return s == "*" || s == "0.0.0.0/0" || s == "::/0" || s == "internet" || s == "any"
}

func rulePort(p *armnetwork.SecurityRulePropertiesFormat) string {
	proto := "tcp"
	if p.Protocol != nil {
		proto = string(*p.Protocol)
	}
	port := "*"
	if p.DestinationPortRange != nil {
		port = *p.DestinationPortRange
	}
	return proto + ":" + port
}

func strPtr(v *string) string {
	if v == nil {
		return ""
	}
	return *v
}

func newFinding(ruleID, title string, sev cspm.Severity, resType, id, name, region string, details map[string]string) cspm.Finding {
	return cspm.Finding{
		RuleID:       ruleID,
		Title:        title,
		Severity:     sev,
		Description:  title,
		Remediation:  "See CastraCloud remediation guidance for " + ruleID + ".",
		Provider:     "azure",
		ResourceType: resType,
		ResourceID:   id,
		ResourceName: name,
		Region:       region,
		Details:      details,
	}
}

func init() {
	connector.Register("azure", New)
}
