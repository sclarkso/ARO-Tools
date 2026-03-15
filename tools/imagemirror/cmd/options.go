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

package cmd

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/spf13/cobra"

	"github.com/Azure/ARO-Tools/tools/cmdutils"
	"github.com/Azure/ARO-Tools/tools/imagemirror/mirror"
)

// RawMirrorOptions represents the initial, unvalidated configuration for image mirror operations.
type RawMirrorOptions struct {
	TargetACR      string
	SourceRegistry string
	Repository     string
	Digest         string
	PullSecretKV   string
	PullSecretName string
	DryRun         bool
}

type validatedMirrorOptions struct {
	*RawMirrorOptions
	DigestHex string // the hex part after the algorithm prefix
}

// ValidatedMirrorOptions represents mirror configuration that has passed validation.
type ValidatedMirrorOptions struct {
	*validatedMirrorOptions
}

// CompletedMirrorOptions represents the final, fully initialized configuration
// for mirror operations.
type CompletedMirrorOptions struct {
	*validatedMirrorOptions
	Copier *mirror.Copier
}

// DefaultMirrorOptions returns a new RawMirrorOptions with default values.
func DefaultMirrorOptions() *RawMirrorOptions {
	return &RawMirrorOptions{}
}

// BindMirrorOptions binds command-line flags to the options.
func BindMirrorOptions(opts *RawMirrorOptions, cmd *cobra.Command) {
	flags := cmd.Flags()
	flags.StringVar(&opts.TargetACR, "target-acr", "", "Target Azure Container Registry name (required)")
	flags.StringVar(&opts.SourceRegistry, "source-registry", "", "Source registry hostname (required)")
	flags.StringVar(&opts.Repository, "repository", "", "Image repository path (required)")
	flags.StringVar(&opts.Digest, "digest", "", "Image digest in algorithm:hex format, e.g. sha256:abc123 (required)")
	flags.StringVar(&opts.PullSecretKV, "pull-secret-kv", "", "Azure Key Vault name containing pull secret")
	flags.StringVar(&opts.PullSecretName, "pull-secret-name", "", "Name of the pull secret in Key Vault")
	flags.BoolVar(&opts.DryRun, "dry-run", false, "Perform a dry run without making changes")

	_ = cmd.MarkFlagRequired("target-acr")
	_ = cmd.MarkFlagRequired("source-registry")
	_ = cmd.MarkFlagRequired("repository")
	_ = cmd.MarkFlagRequired("digest")
}

// Validate performs validation on the raw options.
func (o *RawMirrorOptions) Validate(_ context.Context) (*ValidatedMirrorOptions, error) {
	if o.TargetACR == "" {
		return nil, fmt.Errorf("target-acr is required")
	}
	if o.SourceRegistry == "" {
		return nil, fmt.Errorf("source-registry is required")
	}
	if o.Repository == "" {
		return nil, fmt.Errorf("repository is required")
	}
	if o.Digest == "" {
		return nil, fmt.Errorf("digest is required")
	}

	// validate digest format
	parts := strings.SplitN(o.Digest, ":", 2)
	if len(parts) != 2 || parts[1] == "" {
		return nil, fmt.Errorf("invalid digest format %q: expected algorithm:hex (e.g. sha256:abc123)", o.Digest)
	}

	return &ValidatedMirrorOptions{
		validatedMirrorOptions: &validatedMirrorOptions{
			RawMirrorOptions: o,
			DigestHex:        parts[1],
		},
	}, nil
}

// Complete performs final initialization to create fully usable mirror options.
func (o *ValidatedMirrorOptions) Complete(ctx context.Context) (*CompletedMirrorOptions, error) {
	acrSuffix, err := mirror.GetACRDomainSuffix(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get ACR domain suffix: %w", err)
	}

	targetLoginServer := o.TargetACR + acrSuffix

	// resolve source credentials
	sourceCredential, err := resolveSourceCredential(ctx, o.SourceRegistry, o.PullSecretKV, o.PullSecretName)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve source credentials: %w", err)
	}

	// resolve target credentials
	targetCredential, err := mirror.GetACRCredential(ctx, o.TargetACR)
	if err != nil {
		return nil, fmt.Errorf("failed to get ACR credentials: %w", err)
	}

	copier := mirror.NewCopier(
		o.SourceRegistry, o.Repository, o.Digest, o.DigestHex,
		targetLoginServer,
		sourceCredential, targetCredential,
	)

	return &CompletedMirrorOptions{
		validatedMirrorOptions: o.validatedMirrorOptions,
		Copier:                 copier,
	}, nil
}

func resolveSourceCredential(ctx context.Context, sourceRegistry, pullSecretKV, pullSecretName string) (mirror.Credential, error) {
	// CI registries use oc registry login
	if mirror.IsCIRegistry(sourceRegistry) {
		return mirror.GetOCRegistryCredential(ctx, sourceRegistry)
	}

	// key vault pull secret
	if pullSecretKV != "" && pullSecretName != "" {
		cred, err := cmdutils.GetAzureTokenCredentials()
		if err != nil {
			return mirror.Credential{}, fmt.Errorf("failed to get Azure credentials: %w", err)
		}
		return mirror.FetchPullSecretCredential(ctx, cred, pullSecretKV, pullSecretName, sourceRegistry)
	}

	// anonymous
	return mirror.Credential{}, nil
}

// NormalizeRegistryHost extracts the host[:port] from a registry reference,
// stripping any scheme or path components.
func NormalizeRegistryHost(registry string) string {
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

// IsSameRegistry checks if source and target registries are the same.
func IsSameRegistry(sourceRegistry, targetACR, acrSuffix string) bool {
	return sourceRegistry == targetACR+acrSuffix
}
