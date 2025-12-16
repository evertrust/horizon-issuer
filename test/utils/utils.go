/*
Copyright 2025.

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

package utils

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/tink-crypto/tink-go/v2/aead"
	"github.com/tink-crypto/tink-go/v2/insecurecleartextkeyset"
	"github.com/tink-crypto/tink-go/v2/keyset"

	. "github.com/onsi/ginkgo/v2" // nolint:revive,staticcheck
	. "github.com/onsi/gomega"
)

const (
	certmanagerVersion = "v1.19.1"

	certmanagerURLTmpl = "https://github.com/cert-manager/cert-manager/releases/download/%s/cert-manager.yaml"

	defaultKindBinary  = "kind"
	defaultKindCluster = "kind"

	horizonHelmRepository = "https://repo.evertrust.io/repository/charts"
	horizonNamespace      = "horizon"
	horizonImageRegistry  = "quay.io/evertrust"
	horizonImageName      = "horizon"
	horizonImageTag       = "2.8.0"
	horizonLicensePath    = "test/assets/horizon.lic"
	horizonAdminPassword  = "$6$FgPGge6KVdI9E901$SA1x89egpoUqYqRnqN1wZzMyg3/HcoylrOxpj4oyYxxO82AxH0Cn8Cx8UENUmZbc6MmVjOx8jof/W2e.eEeYn."
)

func warnError(err error) {
	_, _ = fmt.Fprintf(GinkgoWriter, "warning: %v\n", err)
}

// WaitForCertificateReady returns a function suitable for Gomega's Eventually to
// assert that the specified certificate reaches Ready status.
func WaitForCertificateReady(certificateName string) func(Gomega) {
	return func(g Gomega) {
		cmd := exec.Command("kubectl", "get", fmt.Sprintf("certificates/%s", certificateName),
			"-o", "jsonpath={.status.conditions[?(@.type=='Ready')].status}")
		output, err := Run(cmd)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(output).To(Equal("True"), "Certificate %s not ready", certificateName)
	}
}

// WaitForCertificateRequestReady returns a function suitable for Gomega's Eventually to
// assert that the specified certificate request reaches Ready status.
func WaitForCertificateRequestReady(certificateRequestName string) func(Gomega) {
	return func(g Gomega) {
		cmd := exec.Command("kubectl", "get", fmt.Sprintf("certificaterequests/%s", certificateRequestName),
			"-o", "jsonpath={.status.conditions[?(@.type=='Ready')].status}")
		output, err := Run(cmd)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(output).To(Equal("True"), "CertificateRequest %s not ready", certificateRequestName)
	}
}

// WaitForIssuerReady returns a function suitable for Gomega's Eventually to
// assert that the specified issuer (or clusterissuer) reaches Ready status.
func WaitForIssuerReady(resource string, namespace string) func(Gomega) {
	return func(g Gomega) {
		args := []string{
			"get", resource,
			"-o", "jsonpath={.status.conditions[?(@.type=='Ready')].status}",
		}
		if namespace != "" {
			args = append(args, "-n", namespace)
		}
		cmd := exec.Command("kubectl", args...)
		output, err := Run(cmd)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(output).To(Equal("True"), "Issuer %s not ready", resource)
	}
}

// ExpectCertificateRequestAnnotations fetches CertificateRequests for the given certificate request name
// and asserts that their annotations match the expected entries.
func ExpectCertificateRequestAnnotations(certificateRequestName string, expectedAnnotations map[string]string) {
	cmd := exec.Command("kubectl", "get", fmt.Sprintf("certificaterequests/%s", certificateRequestName),
		"-o", "json")
	output, err := Run(cmd)
	Expect(err).NotTo(HaveOccurred(), "Failed to fetch CertificateRequests for %s", certificateRequestName)

	var certificateRequest struct {
		Metadata struct {
			Annotations map[string]string `json:"annotations"`
		} `json:"metadata"`
	}
	err = json.Unmarshal([]byte(output), &certificateRequest)
	Expect(err).NotTo(HaveOccurred(), "Failed to parse CertificateRequest response for %s", certificateRequestName)

	annotations := certificateRequest.Metadata.Annotations
	Expect(annotations).NotTo(BeNil(), "CertificateRequest annotations should be present")
	for key, value := range expectedAnnotations {
		Expect(annotations).To(HaveKeyWithValue(key, value))
	}
}

// Run executes the provided command within this context
func Run(cmd *exec.Cmd) (string, error) {
	dir, _ := GetProjectDir()
	cmd.Dir = dir

	if err := os.Chdir(cmd.Dir); err != nil {
		_, _ = fmt.Fprintf(GinkgoWriter, "chdir dir: %q\n", err)
	}

	cmd.Env = append(os.Environ(), "GO111MODULE=on")
	command := strings.Join(cmd.Args, " ")
	_, _ = fmt.Fprintf(GinkgoWriter, "running: %q\n", command)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return string(output), fmt.Errorf("%q failed with error %q: %w", command, string(output), err)
	}

	return string(output), nil
}

// ApplyManifest applies a manifest using kubectl and asserts success.
func ApplyManifest(manifestPath string, args ...string) {
	cmdArgs := append([]string{"apply", "-f", manifestPath}, args...)
	cmd := exec.Command("kubectl", cmdArgs...)
	_, err := Run(cmd)
	Expect(err).NotTo(HaveOccurred(), "Failed to apply manifest %s", manifestPath)
}

// UninstallCertManager uninstalls the cert manager
func UninstallCertManager() {
	url := fmt.Sprintf(certmanagerURLTmpl, certmanagerVersion)
	cmd := exec.Command("kubectl", "delete", "-f", url)
	if _, err := Run(cmd); err != nil {
		warnError(err)
	}

	// Delete leftover leases in kube-system (not cleaned by default)
	kubeSystemLeases := []string{
		"cert-manager-cainjector-leader-election",
		"cert-manager-controller",
	}
	for _, lease := range kubeSystemLeases {
		cmd = exec.Command("kubectl", "delete", "lease", lease,
			"-n", "kube-system", "--ignore-not-found", "--force", "--grace-period=0")
		if _, err := Run(cmd); err != nil {
			warnError(err)
		}
	}
}

// InstallCertManager installs the cert manager bundle.
func InstallCertManager() error {
	url := fmt.Sprintf(certmanagerURLTmpl, certmanagerVersion)
	cmd := exec.Command("kubectl", "apply", "-f", url)
	if _, err := Run(cmd); err != nil {
		return err
	}
	// Wait for cert-manager-webhook to be ready, which can take time if cert-manager
	// was re-installed after uninstalling on a cluster.
	cmd = exec.Command("kubectl", "wait", "deployment.apps/cert-manager-webhook",
		"--for", "condition=Available",
		"--namespace", "cert-manager",
		"--timeout", "5m",
	)

	_, err := Run(cmd)
	return err
}

// IsCertManagerCRDsInstalled checks if any Cert Manager CRDs are installed
// by verifying the existence of key CRDs related to Cert Manager.
func IsCertManagerCRDsInstalled() bool {
	// List of common Cert Manager CRDs
	certManagerCRDs := []string{
		"certificates.cert-manager.io",
		"issuers.cert-manager.io",
		"clusterissuers.cert-manager.io",
		"certificaterequests.cert-manager.io",
		"orders.acme.cert-manager.io",
		"challenges.acme.cert-manager.io",
	}

	// Execute the kubectl command to get all CRDs
	cmd := exec.Command("kubectl", "get", "crds")
	output, err := Run(cmd)
	if err != nil {
		return false
	}

	// Check if any of the Cert Manager CRDs are present
	crdList := GetNonEmptyLines(output)
	for _, crd := range certManagerCRDs {
		for _, line := range crdList {
			if strings.Contains(line, crd) {
				return true
			}
		}
	}

	return false
}

func InstallHorizon() error {
	horizonImage := fmt.Sprintf("%s/%s:%s", horizonImageRegistry, horizonImageName, horizonImageTag)

	cmd := exec.Command("docker", "pull", horizonImage)
	if _, err := Run(cmd); err != nil {
		return err
	}

	if err := LoadImageToKindClusterWithName(horizonImage); err != nil {
		return err
	}

	cmd = exec.Command("kubectl", "create", "namespace", horizonNamespace)
	if _, err := Run(cmd); err != nil {
		return err
	}

	if keyset, err := GenerateTinkKeyset(); err != nil {
		return err
	} else {
		cmd = exec.Command("kubectl", "create", "secret", "generic", "horizon-secrets",
			"--namespace", horizonNamespace,
			fmt.Sprintf("--from-file=license=%s", horizonLicensePath),
			fmt.Sprintf("--from-literal=keyset=%s", keyset),
			fmt.Sprintf("--from-literal=initialAdminHashPassword=%s", horizonAdminPassword),
		)
		if _, err := Run(cmd); err != nil {
			return err
		}
	}

	cmd = exec.Command("kubectl", "apply", "-f", "test/assets/manifests/local-ca.yml", "-n", horizonNamespace)
	if _, err := Run(cmd); err != nil {
		return err
	}

	cmd = exec.Command("helm", "repo", "add", "evertrust", horizonHelmRepository, "--force-update")
	if _, err := Run(cmd); err != nil {
		return err
	}

	cmd = exec.Command("helm", "upgrade", "horizon", "evertrust/horizon",
		"--namespace", horizonNamespace,
		"--create-namespace",
		"--install",
		"--values", "test/assets/values.yaml",
		"--set", fmt.Sprintf("image.registry=%s", horizonImageRegistry),
		"--set", fmt.Sprintf("image.repository=%s", horizonImageName),
		"--set", fmt.Sprintf("image.tag=%s", horizonImageTag),
	)
	if _, err := Run(cmd); err != nil {
		return err
	}
	// Wait for Horizon to be ready
	cmd = exec.Command("kubectl", "wait", "pods",
		"-l", "app.kubernetes.io/name=horizon",
		"--for", "condition=Ready",
		"--namespace", horizonNamespace,
		"--timeout", "5m",
	)
	if _, err := Run(cmd); err != nil {
		return err
	}

	return nil
}

// UninstallHorizon uninstalls the cert manager
func UninstallHorizon() {
	cmd := exec.Command("kubectl", "delete", "namespace", horizonNamespace)
	if _, err := Run(cmd); err != nil {
		warnError(err)
	}
}

// GenerateTinkKeyset generates a new Tink cleartext keyset as a JSON string.
func GenerateTinkKeyset() (string, error) {
	// Create a new keyset handle using an AEAD template (AES256-GCM here).
	kh, err := keyset.NewHandle(aead.AES256GCMKeyTemplate())
	if err != nil {
		return "", err
	}

	buff := &bytes.Buffer{}

	// nil master key AEAD => cleartext keyset.
	err = insecurecleartextkeyset.Write(kh, keyset.NewJSONWriter(buff))
	if err != nil {
		return "", err
	}

	return buff.String(), nil
}

// LoadImageToKindClusterWithName loads a local docker image to the kind cluster
func LoadImageToKindClusterWithName(name string) error {
	cluster := defaultKindCluster
	if v, ok := os.LookupEnv("KIND_CLUSTER"); ok {
		cluster = v
	}
	kindOptions := []string{"load", "docker-image", name, "--name", cluster}
	kindBinary := defaultKindBinary
	if v, ok := os.LookupEnv("KIND"); ok {
		kindBinary = v
	}
	cmd := exec.Command(kindBinary, kindOptions...)
	_, err := Run(cmd)
	return err
}

// GetNonEmptyLines converts given command output string into individual objects
// according to line breakers, and ignores the empty elements in it.
func GetNonEmptyLines(output string) []string {
	var res []string
	elements := strings.Split(output, "\n")
	for _, element := range elements {
		if element != "" {
			res = append(res, element)
		}
	}

	return res
}

// GetProjectDir will return the directory where the project is
func GetProjectDir() (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return wd, fmt.Errorf("failed to get current working directory: %w", err)
	}
	wd = strings.ReplaceAll(wd, "/test/e2e", "")
	return wd, nil
}

// UncommentCode searches for target in the file and remove the comment prefix
// of the target content. The target content may span multiple lines.
func UncommentCode(filename, target, prefix string) error {
	// false positive
	// nolint:gosec
	content, err := os.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("failed to read file %q: %w", filename, err)
	}
	strContent := string(content)

	idx := strings.Index(strContent, target)
	if idx < 0 {
		return fmt.Errorf("unable to find the code %q to be uncomment", target)
	}

	out := new(bytes.Buffer)
	_, err = out.Write(content[:idx])
	if err != nil {
		return fmt.Errorf("failed to write to output: %w", err)
	}

	scanner := bufio.NewScanner(bytes.NewBufferString(target))
	if !scanner.Scan() {
		return nil
	}
	for {
		if _, err = out.WriteString(strings.TrimPrefix(scanner.Text(), prefix)); err != nil {
			return fmt.Errorf("failed to write to output: %w", err)
		}
		// Avoid writing a newline in case the previous line was the last in target.
		if !scanner.Scan() {
			break
		}
		if _, err = out.WriteString("\n"); err != nil {
			return fmt.Errorf("failed to write to output: %w", err)
		}
	}

	if _, err = out.Write(content[idx+len(target):]); err != nil {
		return fmt.Errorf("failed to write to output: %w", err)
	}

	// false positive
	// nolint:gosec
	if err = os.WriteFile(filename, out.Bytes(), 0644); err != nil {
		return fmt.Errorf("failed to write file %q: %w", filename, err)
	}

	return nil
}
