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

package conda

import (
"github.com/coreos/clair/database"
"github.com/coreos/clair/ext/featurefmt"
"testing"
	"github.com/coreos/clair/pkg/tarutil"

)

func TestCondaFeatureDetection(t *testing.T) {
	testData := []featurefmt.TestData{
		{
			FeatureVersions: []database.FeatureVersion{
				{
					Feature: database.Feature{Name: "apr"},
					Version: "1.6.3",
				},
				{
					Feature: database.Feature{Name: "expat"},
					Version: "2.2.6",
				},
			},
			Files: tarutil.FilesMap{
				"opt/conda/conda-meta/apr-1.6.3-he795440_0.json":
					featurefmt.LoadFileForTest("conda/testdata/conda-meta/apr-1.6.3-he795440_0.json"),
				"opt/conda/envs/another/conda-meta/(expat-2.2.6-h0a44026_0.json":
					featurefmt.LoadFileForTest("conda/testdata/conda-meta/expat-2.2.6-h0a44026_0.json"),
				"opt/conda/envs/another/conda-wrongpath/(expat-2.2.6-h0a44026_0.json":
					featurefmt.LoadFileForTest("conda/testdata/conda-meta/expat-2.2.6-h0a44026_0.json"),
				"root/expat-2.2.6-h0a44026_0.json":
					featurefmt.LoadFileForTest("conda/testdata/conda-meta/expat-2.2.6-h0a44026_0.json"),
			},
		},
	}
	featurefmt.TestLister(t, &lister{}, testData)
}

