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
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/containers/azcontainerregistry"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
)

const (
	acrDefaultUsername = "00000000-0000-0000-0000-000000000000"
	aadTokenScope      = "https://management.azure.com/.default"

	dockerHubRegistryHost = "docker.io"
	dockerHubIndexHost    = "index.docker.io"
	dockerHubRegistryV1   = "registry-1.docker.io"
	dockerHubAPIV1Host    = "https://index.docker.io/v1/"
)

// Credential holds authentication details for registry access.
type Credential struct {
	Username     string
	Password     string
	RefreshToken string
}

// IsEmpty returns true if the credential has no authentication data set.
func (c Credential) IsEmpty() bool {
	return c.Username == "" && c.Password == "" && c.RefreshToken == ""
}

// IsCIRegistry checks if the source registry is a CI registry that requires
// oc registry login. This is determined by the USE_OC_LOGIN_REGISTRIES env var,
// which is set by the CI provisioning step.
func IsCIRegistry(sourceRegistry string) bool {
	sourceHost := NormalizeRegistryHost(sourceRegistry)
	for _, registry := range strings.Fields(os.Getenv("USE_OC_LOGIN_REGISTRIES")) {
		if NormalizeRegistryHost(registry) == sourceHost {
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

	return credentialFromDockerConfig(data, registry)
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

	return credentialFromDockerConfig(decoded, registry)
}

// ExchangeAADForACRToken exchanges an AAD access token for an ACR refresh token
// using the Azure Container Registry SDK. This avoids shelling out to az CLI.
func ExchangeAADForACRToken(ctx context.Context, azureCred azcore.TokenCredential, registryHost string) (Credential, error) {
	token, err := azureCred.GetToken(ctx, policy.TokenRequestOptions{Scopes: []string{aadTokenScope}})
	if err != nil {
		return Credential{}, fmt.Errorf("failed to acquire Azure AD token: %w", err)
	}

	client, err := azcontainerregistry.NewAuthenticationClient(
		"https://"+NormalizeRegistryHost(registryHost), nil,
	)
	if err != nil {
		return Credential{}, fmt.Errorf("failed to create ACR authentication client: %w", err)
	}

	response, err := client.ExchangeAADAccessTokenForACRRefreshToken(
		ctx,
		azcontainerregistry.PostContentSchemaGrantTypeAccessToken,
		NormalizeRegistryHost(registryHost),
		&azcontainerregistry.AuthenticationClientExchangeAADAccessTokenForACRRefreshTokenOptions{
			AccessToken: &token.Token,
		},
	)
	if err != nil {
		return Credential{}, fmt.Errorf("failed to exchange AAD token for ACR refresh token: %w", err)
	}

	if response.RefreshToken == nil || *response.RefreshToken == "" {
		return Credential{}, errors.New("ACR refresh token exchange returned an empty refresh token")
	}

	return Credential{
		Username:     acrDefaultUsername,
		RefreshToken: *response.RefreshToken,
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

// credentialFromDockerConfig parses Docker config JSON and extracts
// credentials for the given registry using exact host matching.
// Returns an empty Credential (not an error) if no credentials are found.
func credentialFromDockerConfig(data []byte, registry string) (Credential, error) {
	var config dockerConfigFile
	if err := json.Unmarshal(data, &config); err != nil {
		return Credential{}, fmt.Errorf("failed to parse Docker config: %w", err)
	}

	sourceHost := NormalizeRegistryHost(registry)
	for registryKey, entry := range config.Auths {
		if NormalizeRegistryHost(registryKey) != sourceHost {
			continue
		}

		cred, err := entry.credential()
		if err != nil {
			return Credential{}, fmt.Errorf("failed to decode auth for %s: %w", registryKey, err)
		}
		return cred, nil
	}

	// no credentials found — return empty credential for anonymous access
	return Credential{}, nil
}

// NormalizeRegistryHost extracts the host[:port] from a registry reference,
// stripping any scheme or path components. Handles Docker Hub aliases.
func NormalizeRegistryHost(input string) string {
	host := strings.TrimSpace(input)
	if host == "" {
		return ""
	}

	if parsed, err := url.Parse(host); err == nil && parsed.Host != "" {
		host = parsed.Host
	}

	host = strings.TrimPrefix(host, "//")
	host = strings.TrimRight(host, "/")
	if idx := strings.Index(host, "/"); idx != -1 {
		host = host[:idx]
	}
	host = strings.ToLower(host)

	// normalize Docker Hub aliases
	switch host {
	case dockerHubIndexHost, dockerHubRegistryV1:
		return dockerHubRegistryHost
	}
	if strings.EqualFold(strings.TrimSpace(input), dockerHubAPIV1Host) {
		return dockerHubRegistryHost
	}

	return host
}

type dockerConfigFile struct {
	Auths map[string]dockerAuthEntry `json:"auths"`
}

type dockerAuthEntry struct {
	Auth          string `json:"auth,omitempty"`
	Username      string `json:"username,omitempty"`
	Password      string `json:"password,omitempty"`
	IdentityToken string `json:"identitytoken,omitempty"`
}

func (e dockerAuthEntry) credential() (Credential, error) {
	switch {
	case strings.TrimSpace(e.IdentityToken) != "":
		return Credential{
			Username:     acrDefaultUsername,
			RefreshToken: e.IdentityToken,
		}, nil
	case strings.TrimSpace(e.Username) != "" || strings.TrimSpace(e.Password) != "":
		return Credential{
			Username: e.Username,
			Password: e.Password,
		}, nil
	case strings.TrimSpace(e.Auth) != "":
		decoded, err := base64.StdEncoding.DecodeString(e.Auth)
		if err != nil {
			return Credential{}, fmt.Errorf("failed to base64-decode auth field: %w", err)
		}
		username, password, found := strings.Cut(string(decoded), ":")
		if !found {
			return Credential{}, errors.New("decoded auth field was missing username:password format")
		}
		return Credential{
			Username: username,
			Password: password,
		}, nil
	default:
		return Credential{}, errors.New("registry auth entry did not contain credentials")
	}
}
