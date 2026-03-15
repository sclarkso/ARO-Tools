// Copyright 2025 Microsoft Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package mirror

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
)

// Credential holds username/password for registry authentication.
type Credential struct {
	Username string
	Password string
}

// IsEmpty returns true if the credential has no username or password set.
func (c Credential) IsEmpty() bool {
	return c.Username == "" && c.Password == ""
}

// IsCIRegistry checks if the source registry is a CI registry that requires
// oc registry login. This is determined by the USE_OC_LOGIN_REGISTRIES env var,
// which is set by the CI provisioning step.
func IsCIRegistry(sourceRegistry string) bool {
	ocLoginRegistries := os.Getenv("USE_OC_LOGIN_REGISTRIES")
	if ocLoginRegistries == "" {
		return false
	}
	for _, registry := range strings.Fields(ocLoginRegistries) {
		if sourceRegistry == registry {
			return true
		}
	}
	return false
}

// GetOCRegistryCredential runs "oc registry login" and parses the resulting
// Docker config JSON to extract credentials for the given registry.
func GetOCRegistryCredential(ctx context.Context, registry string) (Credential, error) {
	tmpFile, err := os.CreateTemp("", "oc-auth-*.json")
	if err != nil {
		return Credential{}, fmt.Errorf("failed to create temp file for oc auth: %w", err)
	}
	// oc registry login expects valid JSON in the target file
	if _, err := tmpFile.Write([]byte(`{"auths":{}}`)); err != nil {
		_ = tmpFile.Close()
		return Credential{}, fmt.Errorf("failed to initialize oc auth file: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		return Credential{}, fmt.Errorf("failed to close oc auth file: %w", err)
	}
	defer os.Remove(tmpFile.Name())

	cmd := exec.CommandContext(ctx, "oc", "registry", "login", "--to", tmpFile.Name())
	if output, err := cmd.CombinedOutput(); err != nil {
		return Credential{}, fmt.Errorf("oc registry login failed: %s: %w", string(output), err)
	}

	data, err := os.ReadFile(tmpFile.Name())
	if err != nil {
		return Credential{}, fmt.Errorf("failed to read oc auth file: %w", err)
	}

	return extractCredentialFromDockerConfig(data, registry)
}

// FetchPullSecretCredential fetches a Docker pull secret from Azure Key Vault
// and returns a credential for the source registry.
// Returns an empty Credential (not an error) if the secret exists but contains
// no credentials for the given registry (e.g. public registries like registry.k8s.io).
func FetchPullSecretCredential(ctx context.Context, azureCred azcore.TokenCredential, vaultName, secretName, registry string) (Credential, error) {
	vaultURL := fmt.Sprintf("https://%s.vault.azure.net", vaultName)
	client, err := azsecrets.NewClient(vaultURL, azureCred, nil)
	if err != nil {
		return Credential{}, fmt.Errorf("failed to create Key Vault client: %w", err)
	}

	resp, err := client.GetSecret(ctx, secretName, "", nil)
	if err != nil {
		return Credential{}, fmt.Errorf("failed to get secret %s: %w", secretName, err)
	}

	if resp.Value == nil {
		return Credential{}, fmt.Errorf("secret %s is empty", secretName)
	}

	// secret is base64-encoded Docker config JSON
	secretValue := *resp.Value
	decoded, err := base64.StdEncoding.DecodeString(secretValue)
	if err != nil {
		// not base64, assume raw JSON
		decoded = []byte(secretValue)
	}

	return extractCredentialFromDockerConfig(decoded, registry)
}

// GetACRCredential gets a credential for an Azure Container Registry
// using the az CLI to get an access token.
func GetACRCredential(ctx context.Context, acrName string) (Credential, error) {
	cmd := exec.CommandContext(ctx, "az", "acr", "login", "--name", acrName,
		"--expose-token", "--output", "tsv", "--query", "accessToken")
	output, err := cmd.Output()
	if err != nil {
		var stderr string
		if exitErr, ok := err.(*exec.ExitError); ok {
			stderr = string(exitErr.Stderr)
		}
		return Credential{}, fmt.Errorf("failed to get ACR access token for %s: %s: %w", acrName, stderr, err)
	}

	return Credential{
		Username: "00000000-0000-0000-0000-000000000000",
		Password: strings.TrimSpace(string(output)),
	}, nil
}

// GetACRDomainSuffix returns the ACR domain suffix for the current Azure cloud
// (e.g., ".azurecr.io" for public Azure).
func GetACRDomainSuffix(ctx context.Context) (string, error) {
	cmd := exec.CommandContext(ctx, "az", "cloud", "show",
		"--query", "suffixes.acrLoginServerEndpoint", "--output", "tsv")
	output, err := cmd.Output()
	if err != nil {
		var stderr string
		if exitErr, ok := err.(*exec.ExitError); ok {
			stderr = string(exitErr.Stderr)
		}
		return "", fmt.Errorf("failed to get ACR domain suffix: %s: %w", stderr, err)
	}
	return strings.TrimSpace(string(output)), nil
}

// extractCredentialFromDockerConfig parses Docker config JSON and extracts
// credentials for the given registry using exact host matching.
func extractCredentialFromDockerConfig(data []byte, registry string) (Credential, error) {
	var dockerConfig struct {
		Auths map[string]struct {
			Auth string `json:"auth"`
		} `json:"auths"`
	}
	if err := json.Unmarshal(data, &dockerConfig); err != nil {
		return Credential{}, fmt.Errorf("failed to parse Docker config: %w", err)
	}

	for registryHost, regAuth := range dockerConfig.Auths {
		if registryHostMatches(registry, registryHost) {
			authDecoded, err := base64.StdEncoding.DecodeString(regAuth.Auth)
			if err != nil {
				return Credential{}, fmt.Errorf("failed to decode auth for %s: %w", registryHost, err)
			}
			parts := strings.SplitN(string(authDecoded), ":", 2)
			if len(parts) != 2 {
				return Credential{}, fmt.Errorf("invalid auth format for %s", registryHost)
			}
			return Credential{
				Username: parts[0],
				Password: parts[1],
			}, nil
		}
	}

	// no credentials found — return empty credential for anonymous access
	return Credential{}, nil
}

// registryHostMatches compares a registry hostname against a Docker config key,
// normalizing both to host[:port] for exact matching.
func registryHostMatches(registry, configKey string) bool {
	return normalizeRegistryHost(registry) == normalizeRegistryHost(configKey)
}

// normalizeRegistryHost extracts the host[:port] from a registry reference,
// stripping any scheme or path components.
func normalizeRegistryHost(registry string) string {
	if strings.Contains(registry, "://") {
		if u, err := url.Parse(registry); err == nil {
			return u.Host
		}
	}
	if idx := strings.Index(registry, "/"); idx != -1 {
		registry = registry[:idx]
	}
	return registry
}
