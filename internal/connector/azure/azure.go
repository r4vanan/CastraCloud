// Package azure implements the CastraCloud CSPM connector for Microsoft Azure
// using DefaultAzureCredential (managed identity or service principal).
package azure

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
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

// New builds an Azure connector from configured service-principal credentials
// or DefaultAzureCredential. The subscription defaults to AZURE_SUBSCRIPTION_ID.
func New(ctx context.Context, cfg connector.Config) (connector.Connector, error) {
	sub := os.Getenv("AZURE_SUBSCRIPTION_ID")
	var cred azcore.TokenCredential
	var err error
	if strings.TrimSpace(cfg.Credentials) != "" {
		var creds struct {
			SubscriptionID string `json:"subscription_id"`
			TenantID       string `json:"tenant_id"`
			ClientID       string `json:"client_id"`
			ClientSecret   string `json:"client_secret"`
		}
		if err := json.Unmarshal([]byte(cfg.Credentials), &creds); err != nil {
			return nil, err
		}
		if creds.SubscriptionID != "" {
			sub = creds.SubscriptionID
		}
		if creds.TenantID == "" || creds.ClientID == "" || creds.ClientSecret == "" {
			return nil, errors.New("azure connector credentials require tenant_id, client_id, and client_secret")
		}
		cred, err = azidentity.NewClientSecretCredential(creds.TenantID, creds.ClientID, creds.ClientSecret, nil)
	} else {
		cred, err = azidentity.NewDefaultAzureCredential(nil)
	}
	if err != nil {
		return nil, err
	}
	if sub == "" {
		return nil, errors.New("azure connector requires subscription_id or AZURE_SUBSCRIPTION_ID")
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
