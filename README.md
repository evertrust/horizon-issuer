<h1 align="center">horizon-issuer</h1>

> A cert-manager issuer allowing you to use your Horizon instance to centralize your Kubernetes certificates issuance.

The documentation for horizon-issuer has been migrated to [docs.evertrust.fr](https://docs.evertrust.fr/horizon-issuer/1/overview).

## Approval of CertificateRequests

horizon-issuer does not approve `CertificateRequest` objects. It submits them to Horizon whether or not something on the cluster has approved them, and it reports the Horizon request status in the `Ready` condition and in the `horizon.evertrust.io/request-status` annotation. If you want requests approved, that is the job of the approval policies you run on the cluster.

When an approver on the cluster denies a request that horizon-issuer had already submitted, horizon-issuer cancels the pending request on Horizon so that nobody waits on it there.

If you rely on cert-manager's built-in approver, it needs the right to approve requests targeting Horizon issuers. [test/assets/manifests/cert-manager-approver-rbac.yml](test/assets/manifests/cert-manager-approver-rbac.yml) shows the `ClusterRole` and `ClusterRoleBinding` to install. See the [cert-manager documentation](https://cert-manager.io/docs/usage/certificaterequest/#approver-controller) for the details.

Before upgrading from 1.1.x or earlier, wait until no `CertificateRequest` is pending on Horizon. Versions up to 1.1.x approved a request themselves once Horizon completed it. This version does not.

## Developing

horizon-issuer uses [mise](https://github.com/jdx/mise) to manage its dependencies. To install it, run:

```sh
curl -fsSL https://mise.jdxcode.dev | sh
```

Then, list available targets:
```sh
mise task ls
```
