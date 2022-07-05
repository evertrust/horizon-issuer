package horizon

import (
	"fmt"
	"github.com/evertrust/horizon-go"
	horizonapi "github.com/evertrust/horizon-issuer/api/v1alpha1"
	"net/url"
)

func HorizonClientFromIssuer(issuerSpec *horizonapi.IssuerSpec, secretData map[string][]byte) (*horizon.Horizon, error) {
	client := new(horizon.Horizon)

	baseUrl, err := url.Parse(issuerSpec.URL)
	if err != nil {
		return nil, fmt.Errorf("%s: %v", "Invalid base URL", err)
	}
	username := string(secretData["username"])
	password := string(secretData["password"])
	client.Init(*baseUrl, username, password)

	if issuerSpec.CaBundle != nil {
		client.Http.SetCaBundle(*issuerSpec.CaBundle)
	}

	if issuerSpec.SkipTLSVerify {
		client.Http.SkipTLSVerify()
	}

	return client, nil
}
