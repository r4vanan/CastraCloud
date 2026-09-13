package connector_test

import (
	"testing"

	"github.com/castracloud/castracloud/internal/connector"
	_ "github.com/castracloud/castracloud/internal/connector/aws"
	_ "github.com/castracloud/castracloud/internal/connector/azure"
	_ "github.com/castracloud/castracloud/internal/connector/gcp"
)

func TestRegisteredProviders(t *testing.T) {
	got := connector.Providers()
	set := map[string]bool{}
	for _, p := range got {
		set[p] = true
	}
	for _, want := range []string{"aws", "azure", "gcp"} {
		if !set[want] {
			t.Errorf("provider %q not registered; registered = %v", want, got)
		}
	}
}
