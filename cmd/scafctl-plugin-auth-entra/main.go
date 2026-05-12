// Package main is the entry point for the scafctl-plugin-auth-entra plugin.
package main

import (
	"github.com/oakwood-commons/scafctl-plugin-auth-entra/internal/entra"

	sdkplugin "github.com/oakwood-commons/scafctl-plugin-sdk/plugin"
)

func main() {
	sdkplugin.ServeAuthHandler(&entra.Plugin{})
}
