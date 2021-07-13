/*******************************************************************************
 * Copyright 2021 EdgeSec Ltd
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing permissions and limitations under
 * the License.
 *
 *******************************************************************************/

package config

import (
	"io/ioutil"
	"log"
	"os"

	"gopkg.in/yaml.v2"
)

var configFile string

type Config struct {
	CSR struct {
		Organization       string `yaml:"organization"`
		OrganizationalUnit string `yaml:"organizationalUnit"`

		Country  string `yaml:"country"`
		Province string `yaml:"province"`
		Locality string `yaml:"locality"`
	} `yaml:"default-csr-values"`
}

var defaultConfig Config

func GetDefaultTLSPort() int {
	return 50025
}

func GetDefaultTLSHost() string {
	hostName, _ := os.Hostname()
	return hostName
}

func GetDefaultTLSCertDir() string {
	homeDir, _ := os.UserHomeDir()
	configDir := homeDir + "/.edgeca"
	if _, err := os.Stat(configDir); os.IsNotExist(err) {
		_ = os.Mkdir(configDir, 0755)
	} else {
	}

	defaultTLSCertDir := configDir + "/certs"

	if _, err := os.Stat(defaultTLSCertDir); os.IsNotExist(err) {
		_ = os.Mkdir(defaultTLSCertDir, 0755)
	} else {
	}

	return defaultTLSCertDir
}

func InitCLIConfiguration() {
	homeDir, _ := os.UserHomeDir()
	configDir := homeDir + "/.edgeca"

	if _, err := os.Stat(configDir); os.IsNotExist(err) {
		_ = os.Mkdir(configDir, 0755)
	} else {
	}

	configFile = configDir + "/config.yaml"
	if _, err := os.Stat(configFile); os.IsNotExist(err) {
	} else {

		yamlFile, err := ioutil.ReadFile(configFile)
		if err != nil {
			log.Fatalln("Could not read config:", err)
		}

		err = yaml.Unmarshal(yamlFile, &defaultConfig)
		if err != nil {
			log.Fatalln("Could not unmarshal config:", err)
		}
	}
}

func SetCSRConfiguration(o string, ou string, c string, p string, l string) error {
	defaultConfig.CSR.Organization = o
	defaultConfig.CSR.OrganizationalUnit = ou
	defaultConfig.CSR.Country = c
	defaultConfig.CSR.Locality = l
	defaultConfig.CSR.Province = p

	marshalled, err := yaml.Marshal(&defaultConfig)
	if err != nil {
		log.Fatalf("error: %v", err)
	}

	ioutil.WriteFile(configFile, marshalled, 0644)
	if err != nil {
		log.Fatalf("error: %v", err)
	}
	log.Println("Updated configuration file " + configFile)
	return nil
}

func GetConfigurationFileContents() (string, error) {
	marshalled, err := yaml.Marshal(&defaultConfig)
	if err != nil {
		log.Fatalf("error: %v", err)
	}

	return string(marshalled), err

}

func GetDefaultOrganization() string {
	return defaultConfig.CSR.Organization
}

func GetDefaultOrganizationalUnit() string {
	return defaultConfig.CSR.OrganizationalUnit
}

func GetDefaultCountry() string {
	return defaultConfig.CSR.Country
}

func GetDefaultLocality() string {
	return defaultConfig.CSR.Locality
}

func GetDefaultProvince() string {
	return defaultConfig.CSR.Province
}
