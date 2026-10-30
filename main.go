package main

import (
	"flag"
	"log"

	"github.com/cipherstash/terraform-provider-cipherstash/internal/provider"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6/tf6server"
)

func main() {
	debug := flag.Bool("debug", false, "serve with debugger reattachment")
	flag.Parse()
	p := provider.New()
	defer p.Close()

	var opts []tf6server.ServeOpt
	if *debug {
		opts = append(opts, tf6server.WithManagedDebug())
	}

	err := tf6server.Serve("terraform.local/cipherstash/cipherstash", func() tfprotov6.ProviderServer {
		return provider.Protocol6(p)
	}, opts...)
	if err != nil {
		p.Close()
		log.Fatal(err)
	}
}
