package horizon

import (
	"context"

	"github.com/evertrust/horizon-go/v2"
	horizonapi "github.com/evertrust/horizon-issuer/api/v1beta1"
	"github.com/go-logr/logr"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

type HealthChecker interface {
	Check(ctx context.Context) error
}

type HealthCheckerBuilder func(logr.Logger, *horizonapi.IssuerSpec, Credentials) (*HorizonHealthChecker, error)

func HealthCheckerFromIssuer(logger logr.Logger, issuerSpec *horizonapi.IssuerSpec, creds Credentials) (*HorizonHealthChecker, error) {
	client, err := ClientFromIssuer(logger, issuerSpec, creds)
	if err != nil {
		return nil, err
	}

	return &HorizonHealthChecker{Client: client, Credentials: creds}, nil
}

type HorizonHealthChecker struct {
	Client      *horizon.APIClient
	Credentials Credentials
}

func (o *HorizonHealthChecker) Check(ctx context.Context) error {
	logger := log.Log.
		WithName("horizon.healthcheck").
		WithValues("url", o.Client.GetConfig().Host)

	logger.V(1).Info("Client setup")
	defer o.Client.CloseIdleConnections()

	_, _, err := o.Client.SecurityPrincipalAPI.SecurityPrincipalSelf(o.Credentials.Context(ctx)).Execute()
	if err != nil {
		logger.V(1).Info("Call to /api/v1/security/principals/self returned an error", "error", err.Error())
		return err
	}
	logger.V(1).Info("Call to /api/v1/security/principals/self returned no error")
	return nil
}
