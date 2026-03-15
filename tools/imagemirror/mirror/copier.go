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
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"
)

const (
	MaxRetries    = 3
	RetryInterval = 30 * time.Second
)

// Copier performs registry-to-registry image copies with retry logic.
type Copier struct {
	srcRef           string
	dstRef           string
	sourceCredential Credential
	targetCredential Credential
}

// NewCopier creates a new Copier for the given image reference and credentials.
func NewCopier(
	sourceRegistry, repository, digest, digestHex string,
	targetLoginServer string,
	sourceCredential, targetCredential Credential,
) *Copier {
	return &Copier{
		srcRef:           fmt.Sprintf("%s/%s@%s", sourceRegistry, repository, digest),
		dstRef:           fmt.Sprintf("%s/%s:%s", targetLoginServer, repository, digestHex),
		sourceCredential: sourceCredential,
		targetCredential: targetCredential,
	}
}

// SrcRef returns the source image reference.
func (c *Copier) SrcRef() string { return c.srcRef }

// DstRef returns the destination image reference.
func (c *Copier) DstRef() string { return c.dstRef }

// CopyWithRetry attempts to copy an image with retry logic for transient failures.
func (c *Copier) CopyWithRetry(ctx context.Context) error {
	logger := logr.FromContextOrDiscard(ctx)
	var lastErr error
	for attempt := 1; attempt <= MaxRetries; attempt++ {
		err := c.copy(ctx)
		if err == nil {
			return nil
		}
		lastErr = err
		if attempt < MaxRetries {
			logger.Info("Image copy failed, retrying", "attempt", attempt, "error", err)
			select {
			case <-time.After(RetryInterval):
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}
	return fmt.Errorf("failed after %d attempts: %w", MaxRetries, lastErr)
}

func (c *Copier) copy(ctx context.Context) error {
	// parse source reference
	srcParts := strings.SplitN(c.srcRef, "/", 2)
	if len(srcParts) != 2 {
		return fmt.Errorf("invalid source reference: %s", c.srcRef)
	}
	srcRegistry := srcParts[0]
	srcRepoAndRef := srcParts[1]

	// parse destination reference
	dstParts := strings.SplitN(c.dstRef, "/", 2)
	if len(dstParts) != 2 {
		return fmt.Errorf("invalid destination reference: %s", c.dstRef)
	}
	dstRegistry := dstParts[0]
	dstRepoAndRef := dstParts[1]

	// set up source repository
	srcRepo, err := remote.NewRepository(fmt.Sprintf("%s/%s", srcRegistry, strings.Split(srcRepoAndRef, "@")[0]))
	if err != nil {
		return fmt.Errorf("failed to create source repository: %w", err)
	}
	srcCred := c.sourceCredential
	srcRepo.Client = &auth.Client{
		Credential: func(ctx context.Context, hostport string) (auth.Credential, error) {
			return auth.Credential{Username: srcCred.Username, Password: srcCred.Password}, nil
		},
	}

	// set up destination repository
	dstRepoName := strings.Split(dstRepoAndRef, ":")[0]
	dstRepo, err := remote.NewRepository(fmt.Sprintf("%s/%s", dstRegistry, dstRepoName))
	if err != nil {
		return fmt.Errorf("failed to create destination repository: %w", err)
	}
	dstCred := c.targetCredential
	dstRepo.Client = &auth.Client{
		Credential: func(ctx context.Context, hostport string) (auth.Credential, error) {
			return auth.Credential{Username: dstCred.Username, Password: dstCred.Password}, nil
		},
	}

	// extract the reference (digest) for the source
	srcReference := ""
	if idx := strings.Index(srcRepoAndRef, "@"); idx != -1 {
		srcReference = srcRepoAndRef[idx+1:]
	}

	// extract the tag for the destination
	dstTag := ""
	if idx := strings.Index(dstRepoAndRef, ":"); idx != -1 {
		dstTag = dstRepoAndRef[idx+1:]
	}

	if _, err := oras.Copy(ctx, srcRepo, srcReference, dstRepo, dstTag, oras.DefaultCopyOptions); err != nil {
		return fmt.Errorf("failed to copy image: %w", err)
	}

	return nil
}
