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

// Package rpm implements a featurefmt.Lister for rpm packages.
package conda

import (
		"io/ioutil"
	"os"
		log "github.com/sirupsen/logrus"

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/ext/featurefmt"
			"github.com/coreos/clair/pkg/commonerr"
	"github.com/coreos/clair/pkg/tarutil"
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
)

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

type lister struct{}

func init() {
	featurefmt.RegisterLister("conda", &lister{})
}

func (l lister) ListFeatures(files tarutil.FilesMap) ([]database.FeatureVersion, error) {
	_, hasFile := files["opt/conda/conda-meta/"]
	if !hasFile {
		return []database.FeatureVersion{}, nil
	}

	// Create a map to store packages and ensure their uniqueness
	packagesMap := make(map[string]database.FeatureVersion)

	// Write the required "Packages" file to disk
	tmpDir, err := ioutil.TempDir(os.TempDir(), "conda")
	defer os.RemoveAll(tmpDir)
	if err != nil {
		log.WithError(err).Error("could not create temporary folder for conda detection")
		return []database.FeatureVersion{}, commonerr.ErrFilesystem
	}

	//Files with metadata
	var filesPackages []string

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

	//parse the files and obtain the packages
	parsePackageFiles(packagesMap, filesPackages)
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
	return []string{"opt/conda/conda-meta/history"}
}
