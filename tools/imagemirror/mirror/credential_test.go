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

func makeDockerConfigAuth(registry, username, password string) []byte {
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

func TestCredentialFromDockerConfig(t *testing.T) {
	// config with multiple auth formats
	rawConfig := []byte(`{
  "auths": {
    "quay.io": {
      "auth": "dXNlcjpwYXNz"
    },
    "https://index.docker.io/v1/": {
      "auth": "ZG9ja2VyOnNlY3JldA=="
    },
    "registry.redhat.io": {
      "username": "robot",
      "password": "token"
    },
    "myregistry.example.com": {
      "identitytoken": "refresh-token-value"
    }
  }
}`)

	tests := []struct {
		name             string
		registry         string
		expectUsername   string
		expectPassword   string
		expectRefresh    string
		expectEmpty      bool
	}{
		{
			name:           "basic auth field",
			registry:       "quay.io",
			expectUsername: "user",
			expectPassword: "pass",
		},
		{
			name:           "docker hub alias",
			registry:       "docker.io",
			expectUsername: "docker",
			expectPassword: "secret",
		},
		{
			name:           "username password fields",
			registry:       "https://registry.redhat.io",
			expectUsername: "robot",
			expectPassword: "token",
		},
		{
			name:          "identity token",
			registry:      "myregistry.example.com",
			expectRefresh: "refresh-token-value",
		},
		{
			name:        "no match returns empty credential",
			registry:    "registry.k8s.io",
			expectEmpty: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cred, err := credentialFromDockerConfig(rawConfig, tc.registry)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tc.expectEmpty {
				if !cred.IsEmpty() {
					t.Errorf("expected empty credential, got %+v", cred)
				}
				return
			}
			if tc.expectRefresh != "" {
				if cred.RefreshToken != tc.expectRefresh {
					t.Errorf("got refresh token %q, want %q", cred.RefreshToken, tc.expectRefresh)
				}
				return
			}
			if cred.Username != tc.expectUsername || cred.Password != tc.expectPassword {
				t.Errorf("got credential %+v, want username=%q password=%q", cred, tc.expectUsername, tc.expectPassword)
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
		{"https://quay.io/v2/", "quay.io"},
		{"https://index.docker.io/v1/", "docker.io"},
		{"registry-1.docker.io", "docker.io"},
		{"docker.io", "docker.io"},
		{"registry.example.com:5000", "registry.example.com:5000"},
		{"https://registry.example.com:5000/v2/", "registry.example.com:5000"},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			if got := NormalizeRegistryHost(tc.input); got != tc.expected {
				t.Errorf("NormalizeRegistryHost(%q) = %q, want %q", tc.input, got, tc.expected)
			}
		})
	}
}

func TestDockerAuthEntryCredential(t *testing.T) {
	t.Run("identity token", func(t *testing.T) {
		entry := dockerAuthEntry{IdentityToken: "refresh-token"}
		cred, err := entry.credential()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cred.RefreshToken != "refresh-token" {
			t.Errorf("got refresh token %q, want %q", cred.RefreshToken, "refresh-token")
		}
	})

	t.Run("username password", func(t *testing.T) {
		entry := dockerAuthEntry{Username: "user", Password: "pass"}
		cred, err := entry.credential()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cred.Username != "user" || cred.Password != "pass" {
			t.Errorf("got %+v, want user/pass", cred)
		}
	})

	t.Run("base64 auth", func(t *testing.T) {
		entry := dockerAuthEntry{Auth: base64.StdEncoding.EncodeToString([]byte("user:pass"))}
		cred, err := entry.credential()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cred.Username != "user" || cred.Password != "pass" {
			t.Errorf("got %+v, want user/pass", cred)
		}
	})

	t.Run("invalid base64 auth format", func(t *testing.T) {
		entry := dockerAuthEntry{Auth: base64.StdEncoding.EncodeToString([]byte("broken"))}
		_, err := entry.credential()
		if err == nil {
			t.Fatal("expected error for missing colon separator")
		}
	})

	t.Run("empty entry", func(t *testing.T) {
		entry := dockerAuthEntry{}
		_, err := entry.credential()
		if err == nil {
			t.Fatal("expected error for empty entry")
		}
	})
}

