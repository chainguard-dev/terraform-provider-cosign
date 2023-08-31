package main

import (
	"context"
	"flag"
	"log"
	"os"

	"github.com/chainguard-dev/terraform-provider-cosign/internal/provider"
	"github.com/google/go-containerregistry/pkg/logs"
	"github.com/hashicorp/terraform-plugin-framework/providerserver"
)

//go:generate terraform fmt -recursive ./examples/
//go:generate go run github.com/hashicorp/terraform-plugin-docs/cmd/tfplugindocs

const version string = "dev"

func main() {
	var debug bool
	flag.BoolVar(&debug, "debug", false, "set to true to run the provider with support for debuggers like delve")
	flag.Parse()

	opts := providerserver.ServeOpts{
		Address: "registry.terraform.io/chainguard-dev/cosign",
		Debug:   debug,
	}

	// Wire up ggcr logs.
	logs.Warn.SetOutput(os.Stderr)
	if debug {
		logs.Progress.SetOutput(os.Stderr)
		logs.Debug.SetOutput(os.Stderr)
	}

	if err := providerserver.Serve(context.Background(), provider.New(version), opts); err != nil {
		log.Fatal(err.Error())
	}
}
