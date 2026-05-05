package horizon

import (
	"errors"
	"testing"

	"github.com/evertrust/horizon-go/v2/models"
)

func TestFormatBasicError(t *testing.T) {
	detail := "Label element 'environment' is mandatory | Label element 'application_name' is mandatory"

	tests := []struct {
		name string
		be   models.BasicError
		want string
	}{
		{
			name: "code title and detail",
			be: func() models.BasicError {
				be := models.BasicError{
					Error:   "REQ-002",
					Title:   "Invalid Request",
					Status:  400,
					Message: "Invalid Request",
				}
				be.SetDetail(detail)
				return be
			}(),
			want: "REQ-002 - Invalid Request: " + detail,
		},
		{
			name: "code and title without detail",
			be: models.BasicError{
				Error: "REQ-002",
				Title: "Invalid Request",
			},
			want: "REQ-002 - Invalid Request",
		},
		{
			name: "title only",
			be: models.BasicError{
				Title: "Invalid Request",
			},
			want: "Invalid Request",
		},
		{
			name: "falls back to message when title is empty",
			be: models.BasicError{
				Error:   "SEC-AUTH-002",
				Message: "Invalid credentials",
			},
			want: "SEC-AUTH-002 - Invalid credentials",
		},
		{
			name: "detail only",
			be: func() models.BasicError {
				be := models.BasicError{}
				be.SetDetail(detail)
				return be
			}(),
			want: detail,
		},
		{
			name: "must not contain the upstream %!s formatting marker",
			be: func() models.BasicError {
				be := models.BasicError{
					Error: "REQ-002",
					Title: "Invalid Request",
				}
				be.SetDetail(detail)
				return be
			}(),
			want: "REQ-002 - Invalid Request: " + detail,
		},
		{
			name: "empty error returns empty string",
			be:   models.BasicError{},
			want: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := formatBasicError(&tc.be)
			if got != tc.want {
				t.Errorf("formatBasicError() = %q, want %q", got, tc.want)
			}
			// Regression guard: the original v1.0.1 bug surfaced as "%!s(" in
			// the rendered string. The cleaned-up message must never contain
			// it, regardless of which fields are populated.
			if containsBadMarker(got) {
				t.Errorf("formatBasicError() leaked unrendered struct fields: %q", got)
			}
		})
	}
}

func TestFormatAPIErrorFallsBackToErrorString(t *testing.T) {
	err := errors.New("plain network error")
	if got := FormatAPIError(err); got != "plain network error" {
		t.Errorf("FormatAPIError() = %q, want %q", got, "plain network error")
	}
	if got := FormatAPIError(nil); got != "" {
		t.Errorf("FormatAPIError(nil) = %q, want empty string", got)
	}
}

func containsBadMarker(s string) bool {
	const marker = "%!s("
	for i := 0; i+len(marker) <= len(s); i++ {
		if s[i:i+len(marker)] == marker {
			return true
		}
	}
	return false
}
