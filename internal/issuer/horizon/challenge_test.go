package horizon

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"net"
	"net/url"
	"reflect"
	"testing"

	"github.com/evertrust/horizon-go/v2/models"
	"github.com/evertrust/horizon-go/v2/utils"
)

const testDNSName = "example.org"

func newCSR(t *testing.T, template x509.CertificateRequest) *x509.CertificateRequest {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &template, key)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatal(err)
	}
	return csr
}

func TestSubjectFromCSR(t *testing.T) {
	csr := newCSR(t, x509.CertificateRequest{
		Subject: pkix.Name{
			Country:            []string{"FR"},
			Organization:       []string{"EverTrust"},
			OrganizationalUnit: []string{"R&D", "Integration"},
			CommonName:         testDNSName,
		},
	})

	got := make(map[string]string)
	for _, element := range subjectFromCSR(csr) {
		got[element.Element] = element.GetValue()
	}

	want := map[string]string{
		"c.1":  "FR",
		"o.1":  "EverTrust",
		"ou.1": "R&D",
		"ou.2": "Integration",
		"cn.1": testDNSName,
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("subjectFromCSR() = %v, want %v", got, want)
	}
}

func TestSubjectFromCSRWithoutSubject(t *testing.T) {
	csr := newCSR(t, x509.CertificateRequest{DNSNames: []string{testDNSName}})

	if got := subjectFromCSR(csr); len(got) != 0 {
		t.Errorf("subjectFromCSR() = %v, want no element", got)
	}
}

func TestSansFromCSR(t *testing.T) {
	uri, err := url.Parse("spiffe://cluster.local/ns/default/sa/example")
	if err != nil {
		t.Fatal(err)
	}
	csr := newCSR(t, x509.CertificateRequest{
		DNSNames:       []string{testDNSName, "www.example.org"},
		EmailAddresses: []string{"team@example.org"},
		IPAddresses:    []net.IP{net.ParseIP("10.0.0.1")},
		URIs:           []*url.URL{uri},
	})

	got := make(map[string][]string)
	for _, san := range sansFromCSR(csr) {
		got[san.GetType()] = san.GetValue()
	}

	want := map[string][]string{
		"DNSNAME":    {testDNSName, "www.example.org"},
		"RFC822NAME": {"team@example.org"},
		"IPADDRESS":  {"10.0.0.1"},
		"URI":        {"spiffe://cluster.local/ns/default/sa/example"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("sansFromCSR() = %v, want %v", got, want)
	}
}

func TestChallengeFromRequest(t *testing.T) {
	secret := func(value string) models.NullableSecretString {
		return *models.NewNullableSecretString(&models.SecretString{Value: *utils.NewNullableString(&value)})
	}

	tests := []struct {
		name          string
		request       models.WebRAEnrollRequestOnGetResponse
		wantChallenge string
		wantOk        bool
	}{
		{
			name: "approved enroll request holding a challenge",
			request: models.WebRAEnrollRequestOnGetResponse{
				Workflow: string(models.WORKFLOW_ENROLL),
				Status:   models.REQUESTSTATUS_APPROVED,
				Password: secret("challenge"),
			},
			wantChallenge: "challenge",
			wantOk:        true,
		},
		{
			name: "approved enroll request without challenge",
			request: models.WebRAEnrollRequestOnGetResponse{
				Workflow: string(models.WORKFLOW_ENROLL),
				Status:   models.REQUESTSTATUS_APPROVED,
			},
		},
		{
			name: "approved enroll request with an empty challenge",
			request: models.WebRAEnrollRequestOnGetResponse{
				Workflow: string(models.WORKFLOW_ENROLL),
				Status:   models.REQUESTSTATUS_APPROVED,
				Password: secret(""),
			},
		},
		{
			name: "pending enroll request",
			request: models.WebRAEnrollRequestOnGetResponse{
				Workflow: string(models.WORKFLOW_ENROLL),
				Status:   models.REQUESTSTATUS_PENDING,
				Password: secret("challenge"),
			},
		},
		{
			name: "approved renew request",
			request: models.WebRAEnrollRequestOnGetResponse{
				Workflow: string(models.WORKFLOW_RENEW),
				Status:   models.REQUESTSTATUS_APPROVED,
				Password: secret("challenge"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			challenge, ok := challengeFromRequest(&tt.request)
			if challenge != tt.wantChallenge || ok != tt.wantOk {
				t.Errorf("challengeFromRequest() = (%q, %v), want (%q, %v)", challenge, ok, tt.wantChallenge, tt.wantOk)
			}
		})
	}
}
