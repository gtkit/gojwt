package gojwt

import "runtime/debug"

var Version = moduleVersion()

func moduleVersion() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "dev"
	}

	for _, dep := range info.Deps {
		if dep.Path != "github.com/gtkit/gojwt" {
			continue
		}
		if dep.Version != "" && dep.Version != "(devel)" {
			return dep.Version
		}
	}

	if info.Main.Path == "github.com/gtkit/gojwt" && info.Main.Version != "" && info.Main.Version != "(devel)" {
		return info.Main.Version
	}

	return "dev"
}
