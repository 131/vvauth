package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestEnvSource(t *testing.T) {
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("shared CLI checks require Node")
	}
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("source checks require Bash")
	}
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(t.TempDir(), "vauth")
	build := exec.Command("go", "build", "-o", binary, "./cmd/vauth")
	build.Dir = root
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build CLI: %v\n%s", err, output)
	}
	checks := exec.Command("node", "--test", "test/env-source.js")
	checks.Dir = root
	checks.Env = append(os.Environ(), "VAUTH_TEST_BINARY="+binary)
	output, err := checks.CombinedOutput()
	t.Logf("%s", output)
	if err != nil {
		t.Fatal(err)
	}
}
