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
)

func TestCondaFeatureDetection(t *testing.T) {
	testData := []featurefmt.TestData{
		{
			FeatureVersions: []database.FeatureVersion{
				{
					Feature: database.Feature{Name: "asn1crypto"},
					Version: "0.24.0",
				},
				{
					Feature: database.Feature{Name: "ca-certificates"},
					Version: "2018.03.07",
				},
				{
					Feature: database.Feature{Name: "certifi"},
					Version: "2018.8.24",
				},
				{
					Feature: database.Feature{Name: "cffi"},
					Version: "1.11.5",
				},
				{
					Feature: database.Feature{Name: "chardet"},
					Version: "3.0.4",
				},
				{
					Feature: database.Feature{Name: "conda"},
					Version: "4.5.11",
				},
				{
					Feature: database.Feature{Name: "conda-env"},
					Version: "2.6.0",
				},
				{
					Feature: database.Feature{Name: "cryptography"},
					Version: "2.3.1",
				},
				{
					Feature: database.Feature{Name: "idna"},
					Version: "2.7",
				},
				{
					Feature: database.Feature{Name: "libcxx"},
					Version: "4.0.1",
				},
				{
					Feature: database.Feature{Name: "libcxxabi"},
					Version: "4.0.1",
				},
				{
					Feature: database.Feature{Name: "libedit"},
					Version: "3.1.20170329",
				},
				{
					Feature: database.Feature{Name: "libffi"},
					Version: "3.2.1",
				},
				{
					Feature: database.Feature{Name: "ncurses"},
					Version: "6.1",
				},
				{
					Feature: database.Feature{Name: "openssl"},
					Version: "1.0.2p",
				},
				{
					Feature: database.Feature{Name: "pip"},
					Version: "10.0.1",
				},
				{
					Feature: database.Feature{Name: "pycosat"},
					Version: "0.6.3",
				},
				{
					Feature: database.Feature{Name: "pycparser"},
					Version: "2.18",
				},
				{
					Feature: database.Feature{Name: "pyopenssl"},
					Version: "18.0.0",
				},
				{
					Feature: database.Feature{Name: "pysocks"},
					Version: "1.6.8",
				},
				{
					Feature: database.Feature{Name: "python"},
					Version: "3.7.0",
				},
				{
					Feature: database.Feature{Name: "python.app"},
					Version: "2",
				},
				{
					Feature: database.Feature{Name: "readline"},
					Version: "7.0",
				},
				{
					Feature: database.Feature{Name: "requests"},
					Version: "2.19.1",
				},
				{
					Feature: database.Feature{Name: "ruamel_yaml"},
					Version: "0.15.46",
				},
				{
					Feature: database.Feature{Name: "setuptools"},
					Version: "40.2.0",
				},
				{
					Feature: database.Feature{Name: "six"},
					Version: "1.11.0",
				},
				{
					Feature: database.Feature{Name: "sqlite"},
					Version: "3.24.0",
				},
				{
					Feature: database.Feature{Name: "tk"},
					Version: "8.6.8",
				},
				{
					Feature: database.Feature{Name: "urllib3"},
					Version: "1.23",
				},
				{
					Feature: database.Feature{Name: "wheel"},
					Version: "0.31.1",
				},
				{
					Feature: database.Feature{Name: "xz"},
					Version: "5.2.4",
				},
				{
					Feature: database.Feature{Name: "yaml"},
					Version: "0.1.7",
				},
				{
					Feature: database.Feature{Name: "zlib"},
					Version: "1.2.11",
				},
				{
					Feature: database.Feature{Name: "xz"},
					Version: "5.2.4",
				},
				{
					Feature: database.Feature{Name: "yaml"},
					Version: "0.1.7",
				},
				{
					Feature: database.Feature{Name: "zlib"},
					Version: "1.2.11",
				},
				{
					Feature: database.Feature{Name: "zlib"},
					Version: "1.2.11",
				},
			},
		},
	}
	featurefmt.TestLister(t, &lister{}, testData)
}

