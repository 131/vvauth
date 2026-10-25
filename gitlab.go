package vvauth

import (
	"fmt"
	"net/url"
	"os/exec"
	"regexp"
	"strings"
)

var scpRemote = regexp.MustCompile(`^[^@]+@[^:]+:(.+)$`)
var nonSlug = regexp.MustCompile(`[^a-z0-9]+`)

func (v *Vauth) Gitlab() error {
	out, err := exec.Command("git", "remote", "get-url", "origin").Output()
	if err != nil {
		return err
	}
	remote := strings.TrimSpace(string(out))
	var project string
	if match := scpRemote.FindStringSubmatch(remote); !strings.Contains(remote, "://") && match != nil {
		project = match[1]
	} else {
		parsed, err := url.Parse(remote)
		if err != nil {
			return err
		}
		project = parsed.Path
	}
	project = strings.TrimSuffix(strings.Trim(project, "/"), ".git")
	if project == "" {
		return fmt.Errorf("Could not resolve the Git project from origin")
	}
	parts := strings.Split(project, "/")
	variables := map[string]string{
		"CI_PROJECT_PATH":      project,
		"CI_PROJECT_NAME":      parts[len(parts)-1],
		"CI_PROJECT_NAMESPACE": strings.Join(parts[:len(parts)-1], "/"),
		"CI_PROJECT_PATH_SLUG": strings.Trim(nonSlug.ReplaceAllString(strings.ToLower(project), "-"), "-"),
	}
	env := &OrderedMap{}
	for _, key := range []string{"CI_PROJECT_PATH", "CI_PROJECT_NAME", "CI_PROJECT_NAMESPACE", "CI_PROJECT_PATH_SLUG"} {
		env.Set(key, variables[key])
	}
	v.PublishEnv(env)
	return nil
}
