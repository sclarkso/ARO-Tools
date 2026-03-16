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
	"fmt"
	"strings"
	"time"

	"github.com/go-logr/logr"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content/oci"
	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"
	"oras.land/oras-go/v2/registry/remote/retry"
)

const (
	MaxRetries    = 3
	RetryInterval = 30 * time.Second
)

// CopyFromRegistry copies an image from one registry to another with retry logic.
func CopyFromRegistry(ctx context.Context, sourceRegistry, repository, digest string, sourceCredential Credential, targetRegistry, targetTag string, targetCredential Credential) (ocispec.Descriptor, error) {
	logger := logr.FromContextOrDiscard(ctx)

	srcRepo, err := newRepository(buildRepositoryReference(sourceRegistry, repository), sourceCredential)
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("failed to create source repository: %w", err)
	}

	dstRepo, err := newRepository(buildRepositoryReference(targetRegistry, repository), targetCredential)
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("failed to create target repository: %w", err)
	}

	var lastErr error
	for attempt := 1; attempt <= MaxRetries; attempt++ {
		desc, err := oras.Copy(ctx, srcRepo, digest, dstRepo, targetTag, oras.DefaultCopyOptions)
		if err == nil {
			return desc, nil
		}
		lastErr = err
		if attempt < MaxRetries {
			logger.Info("Image copy failed, retrying", "attempt", attempt, "error", err)
			select {
			case <-time.After(RetryInterval):
			case <-ctx.Done():
				return ocispec.Descriptor{}, ctx.Err()
			}
		}
	}
	return ocispec.Descriptor{}, fmt.Errorf("failed to copy %s/%s@%s to %s/%s:%s after %d attempts: %w",
		NormalizeRegistryHost(sourceRegistry), repository, digest,
		NormalizeRegistryHost(targetRegistry), repository, targetTag,
		MaxRetries, lastErr)
}

// CopyFromOCILayout copies an image from an OCI layout tar to a registry.
func CopyFromOCILayout(ctx context.Context, imageTarPath, buildTag, targetRegistry, repository string, targetCredential Credential) (ocispec.Descriptor, error) {
	sourceStore, err := oci.NewFromTar(ctx, imageTarPath)
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("failed to open OCI layout tar %s: %w", imageTarPath, err)
	}

	dstRepo, err := newRepository(buildRepositoryReference(targetRegistry, repository), targetCredential)
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("failed to create target repository: %w", err)
	}

	desc, err := oras.Copy(ctx, sourceStore, buildTag, dstRepo, buildTag, oras.DefaultCopyOptions)
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("failed to copy OCI layout %s:%s to %s/%s:%s: %w",
			imageTarPath, buildTag, NormalizeRegistryHost(targetRegistry), repository, buildTag, err)
	}

	return desc, nil
}

func newRepository(reference string, credential Credential) (*remote.Repository, error) {
	repository, err := remote.NewRepository(reference)
	if err != nil {
		return nil, err
	}

	orasCred := auth.Credential{
		Username:     credential.Username,
		Password:     credential.Password,
		RefreshToken: credential.RefreshToken,
	}

	repository.Client = &auth.Client{
		Client:     retry.DefaultClient,
		Cache:      auth.NewCache(),
		Credential: auth.StaticCredential(repository.Reference.Registry, orasCred),
	}

	return repository, nil
}

func buildRepositoryReference(registry, repository string) string {
	return fmt.Sprintf("%s/%s", NormalizeRegistryHost(registry), strings.TrimPrefix(repository, "/"))
}
