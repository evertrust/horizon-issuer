package horizon

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/evertrust/horizon-issuer/api/v1beta1"
)

const (
	testServiceAccountName = "horizon-issuer-sa"
	testToken              = "eyJhbGciOiJSUzI1NiJ9.dummy.signature"
	testProfile            = "issuer"
	principalSelfResponse  = `{"identity":{"identifier":"horizon-issuer-sa"}}`
)

func serviceAccountCredentials(token string) Credentials {
	return Credentials{ServiceAccount: &ServiceAccountCredentials{
		Name:  testServiceAccountName,
		Token: func(context.Context) (string, error) { return token, nil },
	}}
}

// newServiceAccountServer stubs Horizon. It answers /self only when the request carries the
// expected X-API-SVA and X-API-TOKEN headers and rejects everything else with a 401.
func newServiceAccountServer(t *testing.T) (*httptest.Server, *int) {
	t.Helper()
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Header.Get("X-API-SVA") != testServiceAccountName || r.Header.Get("X-API-TOKEN") != testToken {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.Header.Get("X-Api-ID") != "" || r.Header.Get("X-Api-Key") != "" {
			t.Errorf("X-Api-ID/X-Api-Key were sent together with a service account token")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(principalSelfResponse))
	}))
	t.Cleanup(server.Close)
	return server, &calls
}

func TestCredentialsValidate(t *testing.T) {
	tests := []struct {
		name    string
		creds   Credentials
		wantErr bool
	}{
		{name: "nothing set", creds: Credentials{}, wantErr: true},
		{name: "secret", creds: SecretCredentials(corev1.Secret{})},
		{name: "service account", creds: serviceAccountCredentials(testToken)},
		{name: "service account without name", creds: Credentials{ServiceAccount: &ServiceAccountCredentials{Token: func(context.Context) (string, error) { return "", nil }}}, wantErr: true},
		{name: "service account without token provider", creds: Credentials{ServiceAccount: &ServiceAccountCredentials{Name: "sa"}}, wantErr: true},
		{name: "both", creds: Credentials{Secret: &corev1.Secret{}, ServiceAccount: serviceAccountCredentials(testToken).ServiceAccount}, wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.creds.validate(); (err != nil) != tc.wantErr {
				t.Errorf("validate() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func TestClientFromIssuerWithServiceAccount(t *testing.T) {
	server, calls := newServiceAccountServer(t)
	spec := v1beta1.IssuerSpec{URL: server.URL + "/", Profile: testProfile}
	creds := serviceAccountCredentials(testToken)

	client, err := ClientFromIssuer(logr.Discard(), &spec, creds)
	if err != nil {
		t.Fatalf("ClientFromIssuer() error = %v", err)
	}

	// A plain context carries no service account, so the stub must reject the call.
	if _, _, err := client.SecurityPrincipalAPI.SecurityPrincipalSelf(context.Background()).Execute(); err == nil {
		t.Errorf("expected the request without credentials context to be rejected")
	}

	ctx := creds.Context(context.Background())
	if _, _, err := client.SecurityPrincipalAPI.SecurityPrincipalSelf(ctx).Execute(); err != nil {
		t.Errorf("request with service account credentials failed: %v", err)
	}
	if *calls != 2 {
		t.Errorf("server received %d calls, want 2", *calls)
	}
}

func TestClientFromIssuerRejectsMissingCredentials(t *testing.T) {
	spec := v1beta1.IssuerSpec{URL: "https://horizon.example.com", Profile: testProfile}
	if _, err := ClientFromIssuer(logr.Discard(), &spec, Credentials{}); !errors.Is(err, errNoCredentials) {
		t.Errorf("ClientFromIssuer() error = %v, want %v", err, errNoCredentials)
	}
}

func TestClientFromIssuerWithSecretStillWorks(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Api-ID") != "user" || r.Header.Get("X-Api-Key") != "pass" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(principalSelfResponse))
	}))
	t.Cleanup(server.Close)

	spec := v1beta1.IssuerSpec{URL: server.URL, Profile: testProfile}
	secret := corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "creds"},
		Type:       corev1.SecretTypeOpaque,
		Data:       map[string][]byte{"username": []byte("user"), "password": []byte("pass")},
	}
	creds := SecretCredentials(secret)
	client, err := ClientFromIssuer(logr.Discard(), &spec, creds)
	if err != nil {
		t.Fatalf("ClientFromIssuer() error = %v", err)
	}
	if _, _, err := client.SecurityPrincipalAPI.SecurityPrincipalSelf(creds.Context(context.Background())).Execute(); err != nil {
		t.Errorf("request with secret credentials failed: %v", err)
	}
}

func TestHealthCheckerWithServiceAccount(t *testing.T) {
	server, _ := newServiceAccountServer(t)
	spec := v1beta1.IssuerSpec{URL: server.URL, Profile: testProfile}

	checker, err := HealthCheckerFromIssuer(logr.Discard(), &spec, serviceAccountCredentials(testToken))
	if err != nil {
		t.Fatalf("HealthCheckerFromIssuer() error = %v", err)
	}
	if err := checker.Check(context.Background()); err != nil {
		t.Errorf("Check() error = %v", err)
	}

	checker, err = HealthCheckerFromIssuer(logr.Discard(), &spec, serviceAccountCredentials("wrong"))
	if err != nil {
		t.Fatalf("HealthCheckerFromIssuer() error = %v", err)
	}
	if err := checker.Check(context.Background()); err == nil {
		t.Errorf("Check() with a rejected token should fail")
	}

	tokenErr := errors.New("token unavailable")
	checker, err = HealthCheckerFromIssuer(logr.Discard(), &spec, Credentials{ServiceAccount: &ServiceAccountCredentials{
		Name:  testServiceAccountName,
		Token: func(context.Context) (string, error) { return "", tokenErr },
	}})
	if err != nil {
		t.Fatalf("HealthCheckerFromIssuer() error = %v", err)
	}
	if err := checker.Check(context.Background()); err == nil {
		t.Errorf("Check() should surface token provider errors")
	}
}
