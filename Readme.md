<h1 align="center">Horizon Issuer</h1>

> A cert-manager issuer allowing you to use your Horizon instance to centralize your Kubernetes certificates issuance.

## Prerequisites
This software has been testing against the following environment :
- Horizon 2.0.0 and above
- Kubernetes 1.22 and above

## Installation

Add EverTrust's Helm repository to your local repositories :
```shell
helm repo add evertrust https://repo.evertrust.io/repository/charts
```

Install the chart in your cluster :
```shell
helm install cm evertrust/horizon-issuer
```

The default configuration should be fine for most cases. If you want to check out the configuration options, see the [values.yaml](charts/horizon-issuer/values.yaml) file.

Since the chart installs CRDs, please ensure that you have the appropriate permissions when installing it.

## Usage

### Setting up an Horizon issuer
Create an `Issuer` or `ClusterIssuer` object depending on the scope you want to issue certificates on :
```yaml
apiVersion: horizon.evertrust.io/v1alpha1
kind: ClusterIssuer
metadata:
  name: horizon-clusterissuer
spec:
  url: <horizon instance URL> # https://you.evertrust.io
  authSecretName: horizon-credentials
  profile: IssuerProfile
```
Then, provide your Horizon credentials in a secret you may create with :
```shell
kubectl create secret generic issuer-sample-credentials \
 --from-literal=username=<horizon username> \
 --from-literal=password=<horizon password>
```

### Issuing certificates
Now that your issuer is set up, you may reference it when issuing new certificates. This can be done by setting the `issuerRef` key on that certificate :
```yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: demo-cert
spec:
  commonName: demo.org
  secretName: demo-cert
  issuerRef:
    group: horizon.evertrust.io
    kind: ClusterIssuer
    name: horizon-clusterissuer
```

### Securing ingresses
If you are using `ingress-shim` to secure your ingress resources, reference your issuer using the following annotations when creating your ingress :
```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: demo-ingress
  annotations:
    cert-manager.io/issuer-group: horizon.evertrust.io
    cert-manager.io/issuer-kind: ClusterIssuer
    cert-manager.io/issuer: horizon-clusterissuer
    cert-manager.io/common-name: demo.org
```
> **Warning** : be sure to set the `cert-manager.io/common-name` annotation as by default, ingress-shim will generate certificates without any DN. This will cause errors on Horizon's side.


## Configuration

### Revoking deleted certificates

By default, Horizon issuer does not revoke certificates deleted from Kubernetes as cert-manager can reuse the private key kept in the according secret.

If you want to enable that behavior, set the `revokeCertificates` to `true` in your `values.yaml` file.