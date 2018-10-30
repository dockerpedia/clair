// Copyright 2017 clair authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package dpkg implements a featurefmt.Lister for dpkg packages.
package dpkg

import (
	"bufio"
	"regexp"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/ext/featurefmt"
	"github.com/coreos/clair/ext/versionfmt"
	"github.com/coreos/clair/ext/versionfmt/dpkg"
	"github.com/coreos/clair/pkg/tarutil"
	"github.com/coreos/clair/pkg/commonerr"
	"os"
	"fmt"
	"io/ioutil"
	"encoding/json"
	"path/filepath"
)

var (
	dpkgSrcCaptureRegexp      = regexp.MustCompile(`Source: (?P<name>[^\s]*)( \((?P<version>.*)\))?`)
	dpkgSrcCaptureRegexpNames = dpkgSrcCaptureRegexp.SubexpNames()
)

type lister struct{}

type condaPackage struct {
	BaseURL 	*string		`json:"base_url"`
	BuildNumber *int  		`json:"build_number"`
	BuildString string  	`json:"build_string"`
	Channel 	string  	`json:"channel"`
	DistName 	string  	`json:"dist_name"`
	Name 		string  	`json:"name"`
	Platform 	*string 	`json:"platform"`
	Version 	string  	`json:"version"`
}



func init() {
	featurefmt.RegisterLister("dpkg", &lister{})
}

func (l lister) ListFeatures(files tarutil.FilesMap) ([]database.FeatureVersion, error) {
	f, hasFile := files["var/lib/dpkg/status"]
	if !hasFile {
		return []database.FeatureVersion{}, nil
	}

	// Create a map to store packages and ensure their uniqueness
	packagesMap := make(map[string]database.FeatureVersion)

	var pkg database.FeatureVersion
	var err error
	scanner := bufio.NewScanner(strings.NewReader(string(f)))
	for scanner.Scan() {
		line := scanner.Text()

		if strings.HasPrefix(line, "Package: ") {
			// Package line
			// Defines the name of the package

			pkg.Feature.Name = strings.TrimSpace(strings.TrimPrefix(line, "Package: "))
			pkg.Version = ""
		} else if strings.HasPrefix(line, "Source: ") {
			// Source line (Optionnal)
			// Gives the name of the source package
			// May also specifies a version

			srcCapture := dpkgSrcCaptureRegexp.FindAllStringSubmatch(line, -1)[0]
			md := map[string]string{}
			for i, n := range srcCapture {
				md[dpkgSrcCaptureRegexpNames[i]] = strings.TrimSpace(n)
			}

			pkg.Feature.Name = md["name"]
			if md["version"] != "" {
				version := md["version"]
				err = versionfmt.Valid(dpkg.ParserName, version)
				if err != nil {
					log.WithError(err).WithField("version", string(line[1])).Warning("could not parse package version. skipping")
				} else {
					pkg.Version = version
				}
			}
		} else if strings.HasPrefix(line, "Version: ") && pkg.Version == "" {
			// Version line
			// Defines the version of the package
			// This version is less important than a version retrieved from a Source line
			// because the Debian vulnerabilities often skips the epoch from the Version field
			// which is not present in the Source version, and because +bX revisions don't matter
			version := strings.TrimPrefix(line, "Version: ")
			err = versionfmt.Valid(dpkg.ParserName, version)
			if err != nil {
				log.WithError(err).WithField("version", string(line[1])).Warning("could not parse package version. skipping")
			} else {
				pkg.Version = version
			}
		} else if line == "" {
			pkg.Feature.Name = ""
			pkg.Version = ""
		}

		// Add the package to the result array if we have all the informations
		if pkg.Feature.Name != "" && pkg.Version != "" {
			packagesMap[pkg.Feature.Name+"#"+pkg.Version] = pkg
			pkg.Feature.Name = ""
			pkg.Version = ""
		}
	}

	var filesPackages []string
	tmpDir, err := ioutil.TempDir(os.TempDir(), "conda")

	//get the files with metadata of conda
	for fPath, f := range files {
		//detect files only in opt
		packageDir := regexp.MustCompile("opt(/conda/.*)(conda-meta).*.json")
		packageMatch := packageDir.FindStringSubmatch(fPath)
		if len(packageMatch) != 0 {
			fileName := filepath.Base(fPath)
			fileTmp := tmpDir+"/"+fileName
			err = ioutil.WriteFile(fileTmp, f, 0600)
			filesPackages = append(filesPackages, fileTmp)
			if err != nil {
				log.WithError(err).Error("could not create copy file")
				return []database.FeatureVersion{}, commonerr.ErrFilesystem
			}
		}
	}
	parsePackageFiles(packagesMap, filesPackages)

	// Convert the map to a slice
	packages := make([]database.FeatureVersion, 0, len(packagesMap))
	for _, pkg := range packagesMap {
		packages = append(packages, pkg)
	}

	return packages, nil
}


func parsePackageFiles(packagesMap map[string]database.FeatureVersion, files []string) {
	for _, f := range files {
		jsonFile, err := os.Open(f)
		// if we os.Open returns an error then handle it
		if err != nil {
			fmt.Println(err)
		}
		// defer the closing of our jsonFile so that we can parse it later on
		defer jsonFile.Close()

		out, _ := ioutil.ReadAll(jsonFile)

		// we initialize our Users array
		var condaPackage condaPackage

		// we unmarshal our byteArray which contains our
		json.Unmarshal(out, &condaPackage)
		if err != nil {
			log.WithError(err).WithField("output", string(out)).Error("marshall	")
		}
		pkg := database.FeatureVersion{
			Feature: database.Feature{
				Name: condaPackage.Name,
			},
			Version: condaPackage.Version,
		}
		packagesMap[pkg.Feature.Name+"#"+pkg.Version] = pkg
	}
}


func (l lister) RequiredFilenames() []string {
	return []string{"var/lib/dpkg/status"}
}

