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
	"os/exec"
		log "github.com/sirupsen/logrus"

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/ext/featurefmt"
			"github.com/coreos/clair/pkg/commonerr"
	"github.com/coreos/clair/pkg/tarutil"
	"encoding/json"
	"fmt"
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
	// Create a map to store packages and ensure their uniqueness
	packagesMap := make(map[string]database.FeatureVersion)

	// Write the required "Packages" file to disk
	tmpDir, err := ioutil.TempDir(os.TempDir(), "conda")
	defer os.RemoveAll(tmpDir)
	if err != nil {
		log.WithError(err).Error("could not create temporary folder for conda detection")
		return []database.FeatureVersion{}, commonerr.ErrFilesystem
	}

	//Base paths
	condaPath := "/Users/mosorio/miniconda3/"
	binaryPath := condaPath + "bin/conda"
	envsPath := condaPath + "envs"

	//Find the environments of installation conda
	envs := findEnvironments(envsPath)
	for _, env := range envs {
		//Find the packages by env
		findPackagesEnvironment(packagesMap, binaryPath, env)
	}

	// Convert the map to a slice
	packages := make([]database.FeatureVersion, 0, len(packagesMap))
	for _, pkg := range packagesMap {
		packages = append(packages, pkg)
	}

	return packages, nil
}

func (l lister) RequiredFilenames() []string {
	return []string{""}
}

func findPackagesEnvironment(packagesMap map[string]database.FeatureVersion, pathBinary, env string){
	// Ask the packages using conda list.
	out, err := exec.Command(pathBinary, "list", "--json", "-n", env).CombinedOutput()
	if err != nil {
		log.WithError(err).WithField("output", string(out)).Error("could not query RPM")
	}

	// Parse JSON from conda list
	var listPackages []condaPackage
	err = json.Unmarshal(out, &listPackages)
	if err != nil {
		log.WithError(err).WithField("output", string(out)).Error("marshall	")
		fmt.Println(err)
	}

	// Create and add packages to map
	for _, p := range listPackages {
		pkg := database.FeatureVersion{
			Feature: database.Feature{
				Name:  p.Name,
			},
			Version:  p.Version,
		}
		packagesMap[pkg.Feature.Name+"#"+pkg.Version] = pkg
	}
}

func findEnvironments(envsPath string) ([]string){
	envs := []string{"base"}
	directories, _ := ioutil.ReadDir(envsPath)
	for _, envName := range directories{
		envs = append(envs, envName.Name())
	}
	return envs
}

