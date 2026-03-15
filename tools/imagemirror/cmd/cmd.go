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
	logger := logr.FromContextOrDiscard(ctx)

	// check if source and target are the same registry
	acrSuffix, err := mirror.GetACRDomainSuffix(ctx)
	if err != nil {
		return fmt.Errorf("failed to get ACR domain suffix: %w", err)
	}
	if IsSameRegistry(o.SourceRegistry, o.TargetACR, acrSuffix) {
		logger.Info("Source and target registry are the same, skipping mirror")
		return nil
	}

	if o.DryRun {
		logger.Info("DRY_RUN is enabled, skipping image mirror")
		return nil
	}

	logger.Info("Mirroring image", "source", o.Copier.SrcRef(), "target", o.Copier.DstRef())

	if err := o.Copier.CopyWithRetry(ctx); err != nil {
		return fmt.Errorf("failed to mirror image: %w", err)
	}

	logger.Info("Image mirrored successfully")
	return nil
}
