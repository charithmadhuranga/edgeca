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
	"errors"
	"io/ioutil"
	"os"

	log "github.com/sirupsen/logrus"

	"gopkg.in/yaml.v2"
)

var configFile string
var hsmConfigFile string

type Config struct {
	ServerProtocols struct {
		SDSEnabled  bool   `yaml:"sds-enabled"`
		GraphQLPort int    `yaml:"graphql-port"`
		GRPCPort    int    `yaml:"grpc-port"`
		GRPCHost    string `yaml:"grpc-host"`
	} `yaml:"server-protocols"`

	ServerMode struct {
		SelfSigned     bool `yaml:"self-signed"`
		UserCert       bool `yaml:"user-provided"`
		IssuingCert    bool `yaml:"issuing-certificate"`
		TPPPassthrough bool `yaml:"tpp-passthrough"`
	} `yaml:"server-mode"`

	Policy struct {
		Filename           string `yaml:"opa-policy-file"`
		Organization       string `yaml:"default-organization"`
		OrganizationalUnit string `yaml:"default-organizationalUnit"`
		Country            string `yaml:"default-country"`
		Province           string `yaml:"default-province"`
		Locality           string `yaml:"default-locality"`
	} `yaml:"policy"`
	TPP struct {
		Token string `yaml:"token"`
		URL   string `yaml:"url"`
		Zone  string `yaml:"zone"`
	} `yaml:"tpp"`

	UserProvided struct {
		Certificate string `yaml:"certificate"`
		PrivateKey  string `yaml:"private-key"`
	} `yaml:"user-provided"`

	Logging struct {
		Debug bool `yaml:"debug"`
	} `yaml:"logging"`
	HSM struct {
		Path          string `yaml:"path"`
		TokenLabel    string `yaml:"token-label"`
		Pin           string `yaml:"pin"`
		SoftHSMConfig string `yaml:"soft-hsm-config"`
		Enabled       bool   `yaml:"enabled"`
	} `yaml:"hsm"`
}

var defaultConfig Config

func GetDefaultConfdir() string {
	homeDir, _ := os.UserHomeDir()
	return homeDir + "/.edgeca"

}

func GetSoftHSMConfigFile() string {
	return hsmConfigFile
}

func setupSoftHSMLibrary() (string, error) {
	if _, err := os.Stat("/usr/lib/softhsm/libsofthsm2.so"); err == nil {
		return "/usr/lib/softhsm/libsofthsm2.so", nil
	} else if _, err := os.Stat("/usr/local/lib/softhsm/libsofthsm2.so"); err == nil {
		return "/usr/local/lib/softhsm/libsofthsm2.so", nil
	} else {
		return "", errors.New("can't find libsofthsm2.so")
	}
}

func setDefaultHSMConfiguration() {
	defaultPin := "1234"
	defaultID := "edgeca"
	library, err := setupSoftHSMLibrary()
	if err != nil {
		log.Fatalf("%v", err)
	}

	SetHSMConfiguration(library, defaultID, defaultPin, false)

}

func InitCLIConfiguration(configDir string) {

	configFile = configDir + "/config.yaml"

	hsmConfigFile = configDir + "/hsm/softhsm2.conf"

	if _, err := os.Stat(configDir); os.IsNotExist(err) {
		log.Infof("Creating config directory at : %s", configDir)
		_ = os.Mkdir(configDir, 0755)
	} else {
	}

	if _, err := os.Stat(configFile); os.IsNotExist(err) {

		// Create a new config file with default values
		defaultConfig.ServerProtocols.GRPCPort = 50025
		defaultConfig.ServerProtocols.GRPCHost = GetDefaultTLSHost()
		defaultConfig.ServerMode.SelfSigned = true

		setDefaultHSMConfiguration()

		log.Infof("Creating default configuration file at : %s", configFile)
		WriteConfigFile()

	} else {
		log.Debugf("Loading configuration file : %s", configFile)

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

func WriteConfigFile() error {

	marshalled, err := yaml.Marshal(&defaultConfig)
	if err != nil {
		log.Fatalf("error: %v", err)
	}

	ioutil.WriteFile(configFile, marshalled, 0644)
	if err != nil {
		log.Fatalf("error: %v", err)
	}
	log.Debugln("Updated configuration file " + configFile)
	return nil

}

func IsHSMEnaabled() bool {
	return (defaultConfig.HSM.Enabled)
}

func GetHSMConfiguration() (path, tokenLabel, pin string, enabled bool) {
	return defaultConfig.HSM.Path, defaultConfig.HSM.TokenLabel, defaultConfig.HSM.Pin, defaultConfig.HSM.Enabled
}

func SetHSMConfiguration(path, tokenLabel, pin string, enabled bool) {
	defaultConfig.HSM.Path = path
	defaultConfig.HSM.TokenLabel = tokenLabel
	defaultConfig.HSM.Pin = pin
	defaultConfig.HSM.Enabled = enabled
}
func SetCSRConfiguration(o string, ou string, c string, p string, l string) {
	defaultConfig.Policy.Organization = o
	defaultConfig.Policy.OrganizationalUnit = ou
	defaultConfig.Policy.Country = c
	defaultConfig.Policy.Locality = l
	defaultConfig.Policy.Province = p
}

func GetConfigurationFileContents() (string, error) {
	marshalled, err := yaml.Marshal(&defaultConfig)
	if err != nil {
		log.Fatalf("error: %v", err)
	}

	return string(marshalled), err

}

func SetGraphQLPort(port int) {
	defaultConfig.ServerProtocols.GraphQLPort = port
}

func GetGraphQLPort() int {
	return defaultConfig.ServerProtocols.GraphQLPort
}

func SetUseSDS(v bool) {
	defaultConfig.ServerProtocols.SDSEnabled = v
}

func GetUseSDS() bool {
	return defaultConfig.ServerProtocols.SDSEnabled
}

func SetTPPCredentials(tppToken, tppURL, tppZone string) {
	defaultConfig.TPP.Token = tppToken
	defaultConfig.TPP.URL = tppURL
	defaultConfig.TPP.Zone = tppZone
}

func GetTPPCredentials() (tppToken, tppURL, tppZone string) {
	return defaultConfig.TPP.Token, defaultConfig.TPP.URL, defaultConfig.TPP.Zone
}

func GetDefaultOrganization() string {
	return defaultConfig.Policy.Organization
}

func GetDefaultOrganizationalUnit() string {
	return defaultConfig.Policy.OrganizationalUnit
}

func GetDefaultCountry() string {
	return defaultConfig.Policy.Country
}

func GetDefaultLocality() string {
	return defaultConfig.Policy.Locality
}

func GetDefaultProvince() string {
	return defaultConfig.Policy.Province
}

func GetServerTLSHost() string {
	return defaultConfig.ServerProtocols.GRPCHost
}

func SetServerTLSHost(v string) {
	defaultConfig.ServerProtocols.GRPCHost = v
}

func GetServerTLSPort() int {
	return defaultConfig.ServerProtocols.GRPCPort
}

func SetServerTLSPort(v int) {
	defaultConfig.ServerProtocols.GRPCPort = v
}

func GetPolicyFile() string {
	return defaultConfig.Policy.Filename
}

func SetPolicyFile(configPolicy string) {
	defaultConfig.Policy.Filename = configPolicy
}

func GetUserProvidedCACert() (string, string) {
	return defaultConfig.UserProvided.Certificate, defaultConfig.UserProvided.PrivateKey

}

func SetUserProvidedCACert(configCACert, configCAKey string) {
	defaultConfig.UserProvided.Certificate = configCACert
	defaultConfig.UserProvided.PrivateKey = configCAKey

}

func GetDebugLogLevel() bool {
	return defaultConfig.Logging.Debug

}

func SetDebugLogLevel(configDebugLogging bool) {
	defaultConfig.Logging.Debug = configDebugLogging

}

func GetDefaultTLSHost() string {
	hostName, _ := os.Hostname()
	return hostName
}

func UsingSelfSignedMode() bool {
	return defaultConfig.ServerMode.SelfSigned
}

func UsingUserCertMode() bool {
	return defaultConfig.ServerMode.UserCert
}

func UsingIssuingCertMode() bool {
	return defaultConfig.ServerMode.IssuingCert
}

func UsingTPPPassthroughMode() bool {
	return defaultConfig.ServerMode.TPPPassthrough
}

func SetServerMode(mode string) {

	defaultConfig.ServerMode.SelfSigned = false
	defaultConfig.ServerMode.UserCert = false
	defaultConfig.ServerMode.IssuingCert = false
	defaultConfig.ServerMode.TPPPassthrough = false

	switch mode {
	case "self-signed":
		defaultConfig.ServerMode.SelfSigned = true

	case "user-provided":
		defaultConfig.ServerMode.UserCert = true

	case "issuing-certificate":
		defaultConfig.ServerMode.IssuingCert = true

	case "tpp-passthrough":
		defaultConfig.ServerMode.TPPPassthrough = true

	default:
		log.Fatalf("Invalid Mode: %s", mode)
	}

}

func GetServerModeString() (string, error) {

	if defaultConfig.ServerMode.SelfSigned {
		return "self-signed", nil
	} else if defaultConfig.ServerMode.UserCert {
		return "user-provided", nil
	} else if defaultConfig.ServerMode.IssuingCert {
		return "issuing-certificate", nil
	} else if defaultConfig.ServerMode.TPPPassthrough {
		return "tpp-passthrough", nil
	} else {
		return "", errors.New("no Server Mode configured")
	}
}
