package vvauth

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestGitlabPublishesOnlyProjectVariables(t *testing.T) {
	project := t.TempDir()
	for _, args := range [][]string{{"init", "-q", project}, {"-C", project, "remote", "add", "origin", "ssh://git@git.example.test:2222/Team/sub/App.git"}} {
		if out, err := exec.Command("git", args...).CombinedOutput(); err != nil {
			t.Fatalf("git: %v %s", err, out)
		}
	}
	file := filepath.Join(t.TempDir(), "fixture.vauthrc")
	if err := os.WriteFile(file, []byte(`{"env":{"gitlab":true}}`), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("VAUTHRC", file)
	capture, err := os.Create(filepath.Join(t.TempDir(), "stdout"))
	if err != nil {
		t.Fatal(err)
	}
	stdout := os.Stdout
	os.Stdout = capture
	defer func() { os.Stdout = stdout; capture.Close() }()
	before, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(project); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(cwd); err != nil {
			t.Error(err)
		}
	})
	if err := (&Vauth{}).Gitlab(); err != nil {
		t.Fatal(err)
	}
	if _, err := capture.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	output := new(bytes.Buffer)
	if _, err := output.ReadFrom(capture); err != nil {
		t.Fatal(err)
	}
	for key, value := range map[string]string{"CI_PROJECT_PATH": "Team/sub/App", "CI_PROJECT_NAME": "App", "CI_PROJECT_NAMESPACE": "Team/sub", "CI_PROJECT_PATH_SLUG": "team-sub-app"} {
		if !strings.Contains(output.String(), "export "+key+"='"+value+"'") {
			t.Fatalf("missing %s", key)
		}
	}
	if strings.Count(output.String(), "\n") != 8 || strings.Contains(output.String(), "VAULT_TOKEN") {
		t.Fatal("unexpected exports")
	}
	after, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("selected config changed")
	}
	if _, err := os.Stat(filepath.Join(project, ".vauthrc")); !os.IsNotExist(err) {
		t.Fatal("project config created")
	}
}

func TestConstructorGitlabGuardPrecedesAuthentication(t *testing.T) {
	f := newFixture(t, fixtureOptions{})
	file := filepath.Join(t.TempDir(), ".vauthrc")
	document := map[string]any{"vault_addr": f.server.URL, "jwt_auth": map[string]any{"jwt": "test-jwt", "role": "test-role"}, "env": map[string]any{"gitlab": true, "map": map[string]any{"KEEP": "literal"}}}
	body, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, body, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("VAUTHRC", file)
	t.Setenv("VAULT_TOKEN", "")
	keys := []string{"CI_PROJECT_PATH", "CI_PROJECT_NAME", "CI_PROJECT_NAMESPACE", "CI_PROJECT_PATH_SLUG"}
	for _, key := range keys {
		t.Setenv(key, "")
	}
	if _, err := New(); err == nil || !strings.Contains(err.Error(), "Run venv --gitlab first") {
		t.Fatal("constructor accepted missing vars")
	}
	equal(t, len(f.requests), 0)
	for _, key := range keys {
		t.Setenv(key, "provided")
	}
	v, err := New()
	if err != nil {
		t.Fatal(err)
	}
	v.TokenCache = false
	env, err := v.Env(false)
	if err != nil {
		t.Fatal(err)
	}
	value, _ := env.Get("KEEP")
	equal(t, value, "literal")
	if len(f.requests) == 0 {
		t.Fatal("normal auth not performed after initialization")
	}
}
