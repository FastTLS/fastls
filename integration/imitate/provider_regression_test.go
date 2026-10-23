package integration

import (
	fastls "github.com/FastTLS/fastls"
	"testing"
)

func TestCallerHeadersWinOverAllGeneratedPolicies(t *testing.T) {
	for _, value := range []string{"", "application/custom", "text/html"} {
		o := fastls.Options{Headers: map[string]string{"Accept": value, "Sec-Ch-Ua": "custom-hints", "Sec-Fetch-Mode": "custom-mode"}}
		if _, err := useGenerated(&o, "edge/155/windows"); err != nil {
			t.Fatal(err)
		}
		if o.Headers["Accept"] != value || o.Headers["Sec-Ch-Ua"] != "custom-hints" || o.Headers["Sec-Fetch-Mode"] != "custom-mode" {
			t.Fatal(o.Headers)
		}
	}
}
