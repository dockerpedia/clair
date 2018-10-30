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

// Package aptsources implements a featurens.Detector for apt based container
// image layers.
//
// This detector is necessary to determine the precise Debian version when it
// is an unstable version for instance.
package aptsources

import (
			"github.com/coreos/clair/database"
	"github.com/coreos/clair/ext/featurens"
		"github.com/coreos/clair/pkg/tarutil"
)

type detector struct{}

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
	featurens.RegisterDetector("conda-sources", &detector{})
}

func (d detector) Detect(files tarutil.FilesMap) (*database.Namespace, error) {
	_, hasFile := files["opt/conda/conda-meta/history"]
	if !hasFile {
		return nil, nil
	}



	return &database.Namespace{
		Name:          "conda",
		VersionFormat: "4.11",
	}, nil

}

func (d detector) RequiredFilenames() []string {
	return []string{"opt/conda/conda-meta/"}
}
