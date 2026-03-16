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
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"

	"github.com/Azure/ARO-Tools/tools/cmdutils"
	"github.com/Azure/ARO-Tools/tools/imagemirror/mirror"
)

const copyFromOCILayout = "oci-layout"

// RawMirrorOptions represents the initial, unvalidated configuration for image mirror operations.
type RawMirrorOptions struct {
	TargetACR      string
	SourceRegistry string
	Repository     string
	Digest         string
	PullSecretKV   string
	PullSecretName string
	DryRun         bool

	CopyFrom              string
	ImageFilePath         string
	ImageTarFileName      string
	ImageMetadataFileName string
}

type imageSourceMode string

const (
	imageSourceModeRegistry imageSourceMode = "registry"
	imageSourceModeOCI      imageSourceMode = copyFromOCILayout
)

type validatedMirrorOptions struct {
	*RawMirrorOptions
	mode      imageSourceMode
	DigestHex string // the hex part after the algorithm prefix (registry mode only)
}

// ValidatedMirrorOptions represents mirror configuration that has passed validation.
type ValidatedMirrorOptions struct {
	*validatedMirrorOptions
}

type completedMirrorOptions struct {
	targetLoginServer string
	sourceCredential  mirror.Credential
	targetCredential  mirror.Credential
	skipMirror        bool

	// OCI layout fields
	imageTarPath string
	buildTag     string
}

// CompletedMirrorOptions represents the final, fully initialized configuration.
type CompletedMirrorOptions struct {
	*validatedMirrorOptions
	*completedMirrorOptions
}

// DefaultMirrorOptions returns a new RawMirrorOptions with default values.
func DefaultMirrorOptions() *RawMirrorOptions {
	return &RawMirrorOptions{}
}

// BindMirrorOptions binds command-line flags to the options.
func BindMirrorOptions(opts *RawMirrorOptions, cmd *cobra.Command) {
	flags := cmd.Flags()
	flags.StringVar(&opts.TargetACR, "target-acr", "", "Target Azure Container Registry name (required)")
	flags.StringVar(&opts.SourceRegistry, "source-registry", "", "Source registry hostname")
	flags.StringVar(&opts.Repository, "repository", "", "Image repository path (required)")
	flags.StringVar(&opts.Digest, "digest", "", "Image digest in algorithm:hex format, e.g. sha256:abc123")
	flags.StringVar(&opts.PullSecretKV, "pull-secret-kv", "", "Azure Key Vault name containing pull secret")
	flags.StringVar(&opts.PullSecretName, "pull-secret-name", "", "Name of the pull secret in Key Vault")
	flags.BoolVar(&opts.DryRun, "dry-run", false, "Perform a dry run without making changes")
	flags.StringVar(&opts.CopyFrom, "copy-from", "", `Copy source type: empty for registry copy, or "oci-layout"`)
	flags.StringVar(&opts.ImageFilePath, "image-file-path", "", "Directory containing OCI layout inputs (defaults to current directory)")
	flags.StringVar(&opts.ImageTarFileName, "image-tar-file-name", "", "OCI layout tarball file name")
	flags.StringVar(&opts.ImageMetadataFileName, "image-metadata-file-name", "", "Image metadata JSON file name")

	_ = cmd.MarkFlagRequired("target-acr")
	_ = cmd.MarkFlagRequired("repository")
}

// Validate performs validation on the raw options.
func (o *RawMirrorOptions) Validate(_ context.Context) (*ValidatedMirrorOptions, error) {
	if o.TargetACR == "" {
		return nil, fmt.Errorf("target-acr is required")
	}
	if o.Repository == "" {
		return nil, fmt.Errorf("repository is required")
	}

	mode := imageSourceModeRegistry
	switch o.CopyFrom {
	case "":
		// default: registry copy
	case copyFromOCILayout:
		mode = imageSourceModeOCI
	default:
		return nil, fmt.Errorf("unsupported copy-from value %q, expected %q or empty", o.CopyFrom, copyFromOCILayout)
	}

	validated := &validatedMirrorOptions{
		RawMirrorOptions: o,
		mode:             mode,
	}

	switch mode {
	case imageSourceModeRegistry:
		if o.SourceRegistry == "" {
			return nil, fmt.Errorf("source-registry is required for registry copies")
		}
		if o.Digest == "" {
			return nil, fmt.Errorf("digest is required for registry copies")
		}
		parts := strings.SplitN(o.Digest, ":", 2)
		if len(parts) != 2 || parts[1] == "" {
			return nil, fmt.Errorf("invalid digest format %q: expected algorithm:hex (e.g. sha256:abc123)", o.Digest)
		}
		validated.DigestHex = parts[1]
	case imageSourceModeOCI:
		if o.ImageTarFileName == "" {
			return nil, fmt.Errorf("image-tar-file-name is required for oci-layout copies")
		}
		if o.ImageMetadataFileName == "" {
			return nil, fmt.Errorf("image-metadata-file-name is required for oci-layout copies")
		}
	}

	return &ValidatedMirrorOptions{validatedMirrorOptions: validated}, nil
}

// Complete performs final initialization to create fully usable mirror options.
func (o *ValidatedMirrorOptions) Complete(ctx context.Context) (*CompletedMirrorOptions, error) {
	acrSuffix, err := mirror.GetACRDomainSuffix(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get ACR domain suffix: %w", err)
	}

	targetLoginServer := resolveACRLoginServer(o.TargetACR, acrSuffix)
	completed := &completedMirrorOptions{
		targetLoginServer: targetLoginServer,
	}

	// check same-registry shortcut (only for registry mode)
	if o.mode == imageSourceModeRegistry {
		if mirror.NormalizeRegistryHost(o.SourceRegistry) == mirror.NormalizeRegistryHost(targetLoginServer) {
			completed.skipMirror = true
			return &CompletedMirrorOptions{
				validatedMirrorOptions: o.validatedMirrorOptions,
				completedMirrorOptions: completed,
			}, nil
		}
	}

	// get Azure credentials for target ACR
	azureCred, err := cmdutils.GetAzureTokenCredentials()
	if err != nil {
		return nil, fmt.Errorf("failed to get Azure credentials: %w", err)
	}

	// target ACR auth via Azure SDK (no az CLI)
	completed.targetCredential, err = mirror.ExchangeAADForACRToken(ctx, azureCred, targetLoginServer)
	if err != nil {
		return nil, fmt.Errorf("failed to get ACR credentials: %w", err)
	}

	switch o.mode {
	case imageSourceModeRegistry:
		completed.sourceCredential, err = resolveSourceCredential(ctx, azureCred, o.SourceRegistry, o.PullSecretKV, o.PullSecretName)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve source credentials: %w", err)
		}
	case imageSourceModeOCI:
		completed.imageTarPath, completed.buildTag, err = completeOCILayoutInputs(o.ImageFilePath, o.ImageTarFileName, o.ImageMetadataFileName)
		if err != nil {
			return nil, err
		}
	}

	return &CompletedMirrorOptions{
		validatedMirrorOptions: o.validatedMirrorOptions,
		completedMirrorOptions: completed,
	}, nil
}

func resolveSourceCredential(ctx context.Context, azureCred azcore.TokenCredential, sourceRegistry, pullSecretKV, pullSecretName string) (mirror.Credential, error) {
	// CI registries use oc registry login
	if mirror.IsCIRegistry(sourceRegistry) {
		return mirror.GetOCRegistryCredential(ctx, sourceRegistry)
	}

	// key vault pull secret
	if pullSecretKV != "" && pullSecretName != "" {
		return mirror.FetchPullSecretCredential(ctx, azureCred, pullSecretKV, pullSecretName, sourceRegistry)
	}

	// anonymous
	return mirror.Credential{}, nil
}

// IsSameRegistry checks if source and target registries are the same.
func IsSameRegistry(sourceRegistry, targetACR, acrSuffix string) bool {
	return mirror.NormalizeRegistryHost(sourceRegistry) == mirror.NormalizeRegistryHost(targetACR+acrSuffix)
}

func resolveACRLoginServer(targetACR, acrDNSSuffix string) string {
	normalized := mirror.NormalizeRegistryHost(targetACR)
	if strings.Contains(normalized, ".") {
		return normalized
	}
	return normalized + acrDNSSuffix
}

func completeOCILayoutInputs(imageFilePath, imageTarFileName, imageMetadataFileName string) (string, string, error) {
	basePath := imageFilePath
	if strings.TrimSpace(basePath) == "" {
		basePath = "."
	}

	absBasePath, err := filepath.Abs(basePath)
	if err != nil {
		return "", "", fmt.Errorf("failed to resolve image file path %s: %w", basePath, err)
	}

	imageTarPath := filepath.Join(absBasePath, imageTarFileName)
	if _, err := os.Stat(imageTarPath); err != nil {
		return "", "", fmt.Errorf("image tar file %s does not exist at %s: %w", imageTarFileName, absBasePath, err)
	}

	metadataPath := filepath.Join(absBasePath, imageMetadataFileName)
	buildTag, err := readBuildTag(metadataPath)
	if err != nil {
		return "", "", err
	}

	return imageTarPath, buildTag, nil
}

func readBuildTag(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("failed to read image metadata file %s: %w", path, err)
	}

	var metadata struct {
		BuildTag string `json:"build_tag"`
	}
	if err := json.Unmarshal(raw, &metadata); err != nil {
		return "", fmt.Errorf("failed to parse image metadata file %s: %w", path, err)
	}

	if strings.TrimSpace(metadata.BuildTag) == "" {
		return "", fmt.Errorf("build_tag was missing from %s", path)
	}

	return metadata.BuildTag, nil
}
