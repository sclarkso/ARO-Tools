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
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"
)

func makeDockerConfig(registry, username, password string) []byte {
	authStr := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
	config := map[string]interface{}{
		"auths": map[string]interface{}{
			registry: map[string]interface{}{
				"auth": authStr,
			},
		},
	}
	data, _ := json.Marshal(config)
	return data
}

func TestIsCIRegistry(t *testing.T) {
	tests := []struct {
		name           string
		envValue       string
		sourceRegistry string
		expected       bool
	}{
		{
			name:           "env not set",
			envValue:       "",
			sourceRegistry: "registry.build02.ci.openshift.org",
			expected:       false,
		},
		{
			name:           "registry in list",
			envValue:       "registry.build01.ci.openshift.org registry.build02.ci.openshift.org",
			sourceRegistry: "registry.build02.ci.openshift.org",
			expected:       true,
		},
		{
			name:           "registry not in list",
			envValue:       "registry.build01.ci.openshift.org",
			sourceRegistry: "registry.build02.ci.openshift.org",
			expected:       false,
		},
		{
			name:           "public registry not in CI list",
			envValue:       "registry.build02.ci.openshift.org",
			sourceRegistry: "registry.k8s.io",
			expected:       false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.envValue != "" {
				t.Setenv("USE_OC_LOGIN_REGISTRIES", tc.envValue)
			} else {
				os.Unsetenv("USE_OC_LOGIN_REGISTRIES")
			}
			if got := IsCIRegistry(tc.sourceRegistry); got != tc.expected {
				t.Errorf("IsCIRegistry(%q) = %v, want %v", tc.sourceRegistry, got, tc.expected)
			}
		})
	}
}

func TestExtractCredentialFromDockerConfig(t *testing.T) {
	tests := []struct {
		name           string
		config         []byte
		registry       string
		expectUsername  string
		expectPassword string
		expectEmpty    bool
	}{
		{
			name:           "exact match",
			config:         makeDockerConfig("quay.io", "user1", "pass1"),
			registry:       "quay.io",
			expectUsername:  "user1",
			expectPassword: "pass1",
		},
		{
			name:        "no match returns empty credential",
			config:      makeDockerConfig("quay.io", "user1", "pass1"),
			registry:    "registry.k8s.io",
			expectEmpty: true,
		},
		{
			name:           "config key with https scheme",
			config:         makeDockerConfig("https://quay.io", "user2", "pass2"),
			registry:       "quay.io",
			expectUsername:  "user2",
			expectPassword: "pass2",
		},
		{
			name:           "config key with scheme and path",
			config:         makeDockerConfig("https://index.docker.io/v1/", "user3", "pass3"),
			registry:       "index.docker.io",
			expectUsername:  "user3",
			expectPassword: "pass3",
		},
		{
			name:        "substring should not match - evil domain",
			config:      makeDockerConfig("quay.io.evil.com", "user4", "pass4"),
			registry:    "quay.io",
			expectEmpty: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cred, err := extractCredentialFromDockerConfig(tc.config, tc.registry)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tc.expectEmpty {
				if !cred.IsEmpty() {
					t.Errorf("expected empty credential, got %+v", cred)
				}
			} else {
				if cred.Username != tc.expectUsername || cred.Password != tc.expectPassword {
					t.Errorf("got credential %+v, want username=%q password=%q", cred, tc.expectUsername, tc.expectPassword)
				}
			}
		})
	}
}

func TestNormalizeRegistryHost(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"quay.io", "quay.io"},
		{"https://quay.io", "quay.io"},
		{"https://index.docker.io/v1/", "index.docker.io"},
		{"registry.example.com:5000", "registry.example.com:5000"},
		{"https://registry.example.com:5000/v2/", "registry.example.com:5000"},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			if got := normalizeRegistryHost(tc.input); got != tc.expected {
				t.Errorf("normalizeRegistryHost(%q) = %q, want %q", tc.input, got, tc.expected)
			}
		})
	}
}
