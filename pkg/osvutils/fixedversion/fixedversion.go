package fixedversion

import (
	"fmt"
	"strings"

	"github.com/bgriddaluru/gocve/pkg/models"

	"golang.org/x/mod/semver"
)

// findFixedVersion selects the earliest fix for an interval containing the installed
// version. Introduced boundaries are inclusive; fixed boundaries are exclusive.
func Find(affectedPackages []models.AffectedPackage, packageName, installedVersion string) (string, error) {
	installed := "v" + strings.TrimPrefix(installedVersion, "v")
	if !semver.IsValid(installed) {
		return "", fmt.Errorf("invalid installed version %q", installedVersion)
	}

	fixedVersion := ""
	for _, affected := range affectedPackages {
		if affected.Package == nil || affected.Package.Ecosystem != "Go" || affected.Package.Name != packageName {
			continue
		}
		for _, affectedRange := range affected.Ranges {
			if affectedRange.Type != "SEMVER" {
				continue
			}
			introduced := ""
			for _, event := range affectedRange.Events {
				switch {
				case event.Introduced != "":
					introduced = event.Introduced
					if introduced != "0" {
						introduced = "v" + strings.TrimPrefix(introduced, "v")
						if !semver.IsValid(introduced) {
							return "", fmt.Errorf("invalid introduced version %q", event.Introduced)
						}
					}
				case event.Fixed != "":
					fixed := "v" + strings.TrimPrefix(event.Fixed, "v")
					if !semver.IsValid(fixed) {
						return "", fmt.Errorf("invalid fixed version %q", event.Fixed)
					}
					if introduced != "" &&
						(introduced == "0" || semver.Compare(installed, introduced) >= 0) &&
						semver.Compare(installed, fixed) < 0 &&
						(fixedVersion == "" || semver.Compare(fixed, "v"+strings.TrimPrefix(fixedVersion, "v")) < 0) {
						fixedVersion = event.Fixed
					}
					introduced = ""
				case event.LastAffected != "" || event.Limit != "":
					introduced = ""
				}
			}
		}
	}
	return fixedVersion, nil
}
