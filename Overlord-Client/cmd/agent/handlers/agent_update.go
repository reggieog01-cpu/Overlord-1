package handlers

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"overlord-client/cmd/agent/persistence"
	agentRuntime "overlord-client/cmd/agent/runtime"
	"overlord-client/cmd/agent/wire"
)

func HandleAgentUpdate(ctx context.Context, env *agentRuntime.Env, cmdID string, sourcePath string) error {
	sourcePath = strings.TrimSpace(sourcePath)
	if sourcePath == "" {
		return wire.WriteMsg(ctx, env.Conn, wire.CommandResult{Type: "command_result", CommandID: cmdID, OK: false, Message: "missing update path"})
	}

	sourceAbs, err := filepath.Abs(sourcePath)
	if err != nil {
		return wire.WriteMsg(ctx, env.Conn, wire.CommandResult{Type: "command_result", CommandID: cmdID, OK: false, Message: fmt.Sprintf("invalid update path: %v", err)})
	}
	if err := ensureRegularFileOnDisk(sourceAbs); err != nil {
		return wire.WriteMsg(ctx, env.Conn, wire.CommandResult{Type: "command_result", CommandID: cmdID, OK: false, Message: err.Error()})
	}

	if err := wire.WriteMsg(ctx, env.Conn, wire.CommandResult{Type: "command_result", CommandID: cmdID, OK: true}); err != nil {
		return err
	}

	go func() {
		// Let the command_result flush before beginning process replacement.
		time.Sleep(250 * time.Millisecond)
		if err := runAgentUpdate(sourceAbs, env.Cfg.EnablePersistence); err != nil {
			log.Printf("agent_update: %v", err)
			return
		}
		os.Exit(0)
	}()

	return nil
}

func resolveCurrentExecutableOnDisk() (string, error) {
	exePath, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("failed to resolve current executable: %w", err)
	}
	if realPath, err := filepath.EvalSymlinks(exePath); err == nil {
		exePath = realPath
	}
	absPath, err := filepath.Abs(exePath)
	if err != nil {
		return "", fmt.Errorf("failed to resolve absolute executable path: %w", err)
	}
	if err := ensureRegularFileOnDisk(absPath); err != nil {
		return "", fmt.Errorf("current executable is not a regular on-disk file: %w", err)
	}
	return absPath, nil
}

func ensureRegularFileOnDisk(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("file %q is not available on disk: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("file %q is not a regular file", path)
	}
	return nil
}

func copyExecutableAtomic(sourcePath string, targetPath string) error {
	srcFile, err := os.Open(sourcePath)
	if err != nil {
		return fmt.Errorf("failed to open source executable: %w", err)
	}
	defer srcFile.Close()

	dir := filepath.Dir(targetPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create target directory: %w", err)
	}

	tmpFile, err := os.CreateTemp(dir, "agent-update-*.tmp")
	if err != nil {
		return fmt.Errorf("failed to create temp executable: %w", err)
	}
	tmpPath := tmpFile.Name()
	defer func() {
		_ = tmpFile.Close()
		_ = os.Remove(tmpPath)
	}()

	if _, err := io.Copy(tmpFile, srcFile); err != nil {
		return fmt.Errorf("failed to copy executable: %w", err)
	}
	if err := tmpFile.Sync(); err != nil {
		return fmt.Errorf("failed to sync executable: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("failed to close temp executable: %w", err)
	}

	if err := os.Rename(tmpPath, targetPath); err != nil {
		if removeErr := os.Remove(targetPath); removeErr == nil {
			if retryErr := os.Rename(tmpPath, targetPath); retryErr == nil {
				return nil
			}
		}
		return fmt.Errorf("failed to replace executable at %s: %w", targetPath, err)
	}
	return nil
}

func startupTargetPath(enablePersistence bool) (string, bool, error) {
	if !enablePersistence {
		return "", false, nil
	}
	targetPath, err := persistence.TargetPath()
	if err != nil {
		return "", false, fmt.Errorf("failed to resolve startup target path: %w", err)
	}
	targetPath, err = filepath.Abs(targetPath)
	if err != nil {
		return "", false, fmt.Errorf("failed to resolve startup target absolute path: %w", err)
	}
	return targetPath, true, nil
}

func samePath(left string, right string) bool {
	if left == "" || right == "" {
		return false
	}
	return samePathByOS(left, right)
}
