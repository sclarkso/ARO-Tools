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
	"strings"

	"github.com/go-logr/logr"
	"github.com/spf13/cobra"

	"github.com/Azure/ARO-Tools/tools/imagemirror/mirror"
)

// NewMirrorCommand creates the root command for the imagemirror CLI.
func NewMirrorCommand() *cobra.Command {
	opts := DefaultMirrorOptions()

	cmd := &cobra.Command{
		Use:   "imagemirror",
		Short: "Mirror container images between registries",
		Long:  "Mirror container images from a source registry to an Azure Container Registry",
		RunE: func(cmd *cobra.Command, args []string) error {
			return opts.Run(cmd.Context())
		},
	}

	BindMirrorOptions(opts, cmd)

	return cmd
}

// Run executes the full validate → complete → run pipeline.
func (opts *RawMirrorOptions) Run(ctx context.Context) error {
	validated, err := opts.Validate(ctx)
	if err != nil {
		return fmt.Errorf("validation failed: %w", err)
	}

	completed, err := validated.Complete(ctx)
	if err != nil {
		return fmt.Errorf("completion failed: %w", err)
	}

	return completed.Run(ctx)
}

// Run performs the actual image mirror operation.
func (o *CompletedMirrorOptions) Run(ctx context.Context) error {
	logger := logr.FromContextOrDiscard(ctx).WithValues(
		"targetACR", o.TargetACR,
		"repository", o.Repository,
		"mode", o.mode,
	)

	if o.skipMirror {
		logger.Info("Source and target registry are the same, skipping mirror")
		return nil
	}

	if o.DryRun {
		logger.Info("Dry-run enabled, skipping image mirror")
		return nil
	}

	switch o.mode {
	case imageSourceModeRegistry:
		tag := strings.TrimPrefix(o.Digest, "sha256:")
		desc, err := mirror.CopyFromRegistry(ctx,
			o.SourceRegistry, o.Repository, o.Digest, o.sourceCredential,
			o.targetLoginServer, tag, o.targetCredential,
		)
		if err != nil {
			return err
		}
		logger.Info("Image mirrored successfully", "digest", desc.Digest.String(), "tag", tag)

	case imageSourceModeOCI:
		desc, err := mirror.CopyFromOCILayout(ctx,
			o.imageTarPath, o.buildTag,
			o.targetLoginServer, o.Repository, o.targetCredential,
		)
		if err != nil {
			return err
		}
		logger.Info("Image mirrored from OCI layout", "digest", desc.Digest.String(), "tag", o.buildTag)

	default:
		return fmt.Errorf("unsupported image source mode %q", o.mode)
	}

	return nil
}
