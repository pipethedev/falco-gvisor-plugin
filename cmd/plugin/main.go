// Command plugin builds libgvisor.so, the Falco gvisor plugin.
package main

import (
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins/extractor"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins/source"
)

func init() {
	plugins.SetFactory(func() plugins.Plugin {
		p := &gvisorPlugin{}
		source.Register(p)
		extractor.Register(p)
		return p
	})
}

func main() {}
