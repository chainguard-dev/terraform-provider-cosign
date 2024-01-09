package provider

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/sigstore/cosign/pkg/cosign/env"
	"github.com/sigstore/cosign/pkg/providers/filesystem"
)

func TestAccAvailableCredentials(t *testing.T) {
	dir := t.TempDir()
	tmp, err := os.Create(filepath.Join(dir, "foo"))
	if err != nil {
		t.Fatal(err)
	}
	defer tmp.Close()

	for _, c := range []struct {
		desc      string
		pre, post func(t *testing.T) // pre- and post-test steps
		env       map[string]string
		checks    []resource.TestCheckFunc
	}{{
		desc: "no env",
		env:  nil,
		pre: func(t *testing.T) {
			// If this test is running on GHA, we will never have a scenario where we don't have some ambient credentials.
			if os.Getenv(string(env.VariableGitHubRequestToken)) != "" {
				t.Skip("Skipping no-env check since we're running on GitHub Actions")
			}
		},
		checks: []resource.TestCheckFunc{
			resource.TestCheckResourceAttr("data.cosign_available_credentials.available", "available.#", "0"),
		},
	}, {
		desc: "github",
		env: map[string]string{
			string(env.VariableGitHubRequestToken): "foo",
			string(env.VariableGitHubRequestURL):   "bar",
		},
		checks: []resource.TestCheckFunc{
			resource.TestCheckResourceAttr("data.cosign_available_credentials.available", "available.#", "1"),
			resource.TestCheckResourceAttr("data.cosign_available_credentials.available", "available.0", "github-actions"),
		},
	}, {
		desc: "filesystem and github",
		env: map[string]string{
			string(env.VariableGitHubRequestToken): "foo",
			string(env.VariableGitHubRequestURL):   "bar",
		},
		pre:  func(*testing.T) { filesystemTokenPath = tmp.Name() },
		post: func(*testing.T) { filesystemTokenPath = filesystem.FilesystemTokenPath },
		checks: []resource.TestCheckFunc{
			resource.TestCheckResourceAttr("data.cosign_available_credentials.available", "available.#", "2"),
			resource.TestCheckResourceAttr("data.cosign_available_credentials.available", "available.0", "filesystem"),
			resource.TestCheckResourceAttr("data.cosign_available_credentials.available", "available.1", "github-actions"),
		},
	}, {
		desc: "interactive and github",
		env: map[string]string{
			string(env.VariableGitHubRequestToken): "foo",
			string(env.VariableGitHubRequestURL):   "bar",
			"TF_COSIGN_LOCAL":                      "true",
		},
		checks: []resource.TestCheckFunc{
			resource.TestCheckResourceAttr("data.cosign_available_credentials.available", "available.#", "2"),
			resource.TestCheckResourceAttr("data.cosign_available_credentials.available", "available.0", "github-actions"),
			resource.TestCheckResourceAttr("data.cosign_available_credentials.available", "available.1", "interactive"),
		},
	}, {
		desc: "all together now",
		env: map[string]string{
			string(env.VariableGitHubRequestToken): "foo",
			string(env.VariableGitHubRequestURL):   "bar",
			"TF_COSIGN_LOCAL":                      "true",
		},
		pre:  func(*testing.T) { filesystemTokenPath = tmp.Name() },
		post: func(*testing.T) { filesystemTokenPath = filesystem.FilesystemTokenPath },
		checks: []resource.TestCheckFunc{
			resource.TestCheckResourceAttr("data.cosign_available_credentials.available", "available.#", "3"),
			resource.TestCheckResourceAttr("data.cosign_available_credentials.available", "available.0", "filesystem"),
			resource.TestCheckResourceAttr("data.cosign_available_credentials.available", "available.1", "github-actions"),
			resource.TestCheckResourceAttr("data.cosign_available_credentials.available", "available.2", "interactive"),
		},
	}} {
		t.Run(c.desc, func(t *testing.T) {
			if c.pre != nil {
				c.pre(t)
			}
			if c.post != nil {
				defer c.post(t)
			}
			for k, v := range c.env {
				t.Setenv(k, v)
			}
			resource.Test(t, resource.TestCase{
				PreCheck:                 func() { testAccPreCheck(t) },
				ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
				Steps: []resource.TestStep{{
					Config: `data "cosign_available_credentials" "available" {}`,
					Check:  resource.ComposeAggregateTestCheckFunc(c.checks...),
				}},
			})
		})
	}
}
