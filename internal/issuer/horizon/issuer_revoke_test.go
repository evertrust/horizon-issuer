/*
Copyright 2025 EVERTRUST

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package horizon

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	"github.com/evertrust/horizon-go/v2/models"
)

const alreadyRevokedResponse = `{"error":"TEST-ERROR","title":"Certificate is already revoked","message":"Certificate is already revoked","status":400}`

// revokeSubmittedResponse is what Horizon answers once it has accepted a revocation.
const revokeSubmittedResponse = `{"module":"webra","workflow":"revoke","_id":"revoke-request-id","template":{},"holderId":"holder",
"lastModificationDate":0,"profile":"issuer","registrationDate":0,"removeAt":0,"status":"completed"}`

func horizonError(title string, status int) string {
	return fmt.Sprintf(`{"error":"TEST-ERROR","title":%q,"message":%q,"status":%d}`, title, title, status)
}

// fakeHorizonForRevoke answers the revoke submission with revokeStatus and revokeBody, and the
// certificate lookup with lookup. A nil lookup means Horizon does not know the certificate.
type fakeHorizonForRevoke struct {
	revokeStatus int
	revokeBody   string
	lookup       *models.CertificateWithPermissionsResponse

	revokes    int
	lookups    int
	lookupBody map[string]string
}

func (f *fakeHorizonForRevoke) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/api/v1/requests/submit":
		f.revokes++
		w.WriteHeader(f.revokeStatus)
		_, _ = w.Write([]byte(f.revokeBody))
	case r.Method == http.MethodPost && r.URL.Path == "/api/v1/certificates/find":
		f.lookups++
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &f.lookupBody)
		if f.lookup == nil {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(horizonError("Certificate not found", http.StatusNotFound)))
			return
		}
		out, _ := json.Marshal(f.lookup)
		_, _ = w.Write(out)
	default:
		http.NotFound(w, r)
	}
}

func TestRevokeCertificate(t *testing.T) {
	issued := newTestCertificatePEM(t, "issued.example")

	tests := []struct {
		name             string
		revokeStatus     int
		revokeBody       string
		lookup           *models.CertificateWithPermissionsResponse
		wantAlready      bool
		wantErr          string
		wantLookup       bool
		wantRevokeErrMsg bool
	}{
		{
			name:         "revocation accepted by Horizon",
			revokeStatus: http.StatusOK,
			revokeBody:   revokeSubmittedResponse,
		},
		{
			name:         "certificate Horizon already revoked counts as revoked",
			revokeStatus: http.StatusBadRequest,
			revokeBody:   alreadyRevokedResponse,
			lookup:       horizonCertificate(issued, true),
			wantAlready:  true,
			wantLookup:   true,
		},
		{
			name:             "refusal for a certificate that is still valid is reported",
			revokeStatus:     http.StatusBadRequest,
			revokeBody:       horizonError("Invalid request", http.StatusBadRequest),
			lookup:           horizonCertificate(issued, false),
			wantErr:          "Invalid request",
			wantLookup:       true,
			wantRevokeErrMsg: true,
		},
		{
			name:             "refusal is reported when Horizon does not know the certificate",
			revokeStatus:     http.StatusBadRequest,
			revokeBody:       alreadyRevokedResponse,
			wantErr:          "Certificate not found",
			wantLookup:       true,
			wantRevokeErrMsg: true,
		},
		{
			name:             "server errors are reported",
			revokeStatus:     http.StatusInternalServerError,
			revokeBody:       horizonError("Internal error", http.StatusInternalServerError),
			lookup:           horizonCertificate(issued, false),
			wantErr:          "Internal error",
			wantLookup:       true,
			wantRevokeErrMsg: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			horizon := &fakeHorizonForRevoke{revokeStatus: tc.revokeStatus, revokeBody: tc.revokeBody, lookup: tc.lookup}
			issuer, _ := newIssuerForServer(t, horizon)

			certificateRequest := &cmapi.CertificateRequest{Status: cmapi.CertificateRequestStatus{Certificate: []byte(issued)}}
			alreadyRevoked, err := issuer.RevokeCertificate(context.Background(), certificateRequest)

			if tc.wantErr == "" && err != nil {
				t.Fatalf("RevokeCertificate() error = %v", err)
			}
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("RevokeCertificate() error = nil, want one containing %q", tc.wantErr)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Errorf("RevokeCertificate() error = %q, want it to contain %q", err, tc.wantErr)
				}
				if tc.wantRevokeErrMsg && !errors.Is(err, errRevokeCertificate) {
					t.Errorf("RevokeCertificate() error = %q, want it to say the revocation failed", err)
				}
			}
			if alreadyRevoked != tc.wantAlready {
				t.Errorf("alreadyRevoked = %v, want %v", alreadyRevoked, tc.wantAlready)
			}
			if horizon.revokes != 1 {
				t.Errorf("revocation submitted %d times, want 1", horizon.revokes)
			}
			if gotLookup := horizon.lookups > 0; gotLookup != tc.wantLookup {
				t.Errorf("certificate looked up on Horizon = %v, want %v", gotLookup, tc.wantLookup)
			}
		})
	}
}

// The request holds the whole chain. Only the leaf is looked up on Horizon.
func TestRevokeCertificateLooksUpTheLeafOnly(t *testing.T) {
	leaf := newTestCertificatePEM(t, "leaf.example")
	intermediate := newTestCertificatePEM(t, "intermediate.example")

	horizon := &fakeHorizonForRevoke{
		revokeStatus: http.StatusBadRequest,
		revokeBody:   alreadyRevokedResponse,
		lookup:       horizonCertificate(leaf, true),
	}
	issuer, _ := newIssuerForServer(t, horizon)

	certificateRequest := &cmapi.CertificateRequest{Status: cmapi.CertificateRequestStatus{Certificate: []byte(leaf + intermediate)}}
	alreadyRevoked, err := issuer.RevokeCertificate(context.Background(), certificateRequest)
	if err != nil {
		t.Fatalf("RevokeCertificate() error = %v", err)
	}
	if !alreadyRevoked {
		t.Error("alreadyRevoked = false, want true")
	}
	if got := horizon.lookupBody["pem"]; got != leaf {
		t.Errorf("looked up PEM = %q, want the leaf only", got)
	}
}

func horizonCertificate(certificatePem string, revoked bool) *models.CertificateWithPermissionsResponse {
	certificate := models.NewCertificate("certificate-id", certificatePem, "CN=test", false, "holder", "CN=test", "ec-256",
		[]models.CertificateMetadata{}, "webra", 0, 0, "public-key-thumbprint", revoked, true, "01", "SHA256WITHECDSA",
		[]models.SubjectAlternateName{}, "thumbprint")
	return models.NewCertificateWithPermissionsResponse(*certificate, models.CertificatePermissions{})
}

// newTestCertificatePEM returns a throwaway self-signed certificate.
func newTestCertificatePEM(t *testing.T, commonName string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}
