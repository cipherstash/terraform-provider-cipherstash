package main

import (
	"errors"
	"flag"
	"log"

	"github.com/bndry-co/terraform-provider-cipherstash/internal/provider"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6/tf6server"
)

func main() {
	debug := flag.Bool("debug", false, "serve with debugger reattachment")
	flag.Parse()
	p := provider.New()
	var opts []tf6server.ServeOpt
	if *debug {
		opts = append(opts, tf6server.WithManagedDebug())
	}

	err := func() (err error) {
		defer func() {
			if closeErr := p.Close(); closeErr != nil {
				err = errors.Join(err, errors.New("could not close SDK authentication"))
			}
		}()

		return tf6server.Serve("terraform.local/bndry-co/cipherstash", func() tfprotov6.ProviderServer {
			return provider.Protocol6(p)
		}, opts...)
	}()
	if err != nil {
		log.Fatal(err)
	}
}
