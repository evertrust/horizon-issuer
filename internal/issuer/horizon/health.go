package horizon

import (
	"github.com/evertrust/horizon-go"
	horizonapi "github.com/evertrust/horizon-issuer/api/v1alpha1"
)

type HealthChecker interface {
	Check() error
}

type HealthCheckerBuilder func(*horizonapi.IssuerSpec, map[string][]byte) (*HorizonHealthChecker, error)

func HorizonHealthCheckerFromIssuer(issuerSpec *horizonapi.IssuerSpec, secretData map[string][]byte) (*HorizonHealthChecker, error) {
	client, err := HorizonClientFromIssuer(issuerSpec, secretData)
	if err != nil {
		return nil, err
	}

	return &HorizonHealthChecker{Client: *client}, nil
}

type HorizonHealthChecker struct {
	Client horizon.Horizon
}

func (o *HorizonHealthChecker) Check() error {
	_, err := o.Client.Http.Get("/api/v1/security/principals/self")
	if err != nil {
		return err
	}
	return nil
}
