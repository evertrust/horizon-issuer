//go:build e2e

package e2e

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHorizonAPI(t *testing.T) {
	for _, test := range []struct {
		name        string
		exitCode    string
		waitFailure bool
	}{
		{name: "response from completed pod", exitCode: "0"},
		{name: "HTTP failure preserves response", exitCode: "22"},
		{name: "timeout still cleans up", exitCode: "0", waitFailure: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			calls := filepath.Join(dir, "calls")
			script := `#!/bin/sh
printf '%s\n' "$*" >> "$KUBECTL_CALLS"
case "$1" in
 run) printf 'pod created\n' ;;
 wait) test "$WAIT_FAILURE" != true ;;
 logs) printf '{"status":"canceled"}' ;;
 get) printf '%s' "$CURL_EXIT_CODE" ;;
esac
`
			if err := os.WriteFile(filepath.Join(dir, "kubectl"), []byte(script), 0o700); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
			t.Setenv("KUBECTL_CALLS", calls)
			t.Setenv("CURL_EXIT_CODE", test.exitCode)
			if test.waitFailure {
				t.Setenv("WAIT_FAILURE", "true")
			} else {
				t.Setenv("WAIT_FAILURE", "false")
			}
			output, err := horizonAPI(http.MethodGet, "/api/v1/requests", "")
			wantError := test.exitCode != "0" || test.waitFailure
			if (err != nil) != wantError {
				t.Fatalf("unexpected error: %v", err)
			}
			if !test.waitFailure && output != `{"status":"canceled"}` {
				t.Fatalf("unexpected response: %q", output)
			}
			data, err := os.ReadFile(calls)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(data), "delete pod horizon-api-") {
				t.Fatalf("probe pod was not cleaned up: %s", data)
			}
		})
	}
}
