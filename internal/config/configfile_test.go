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
	"os"
	"testing"
)

func TestConfig(t *testing.T) {

	// delete config file
	homedir, _ := os.UserHomeDir()
	filename := homedir + "/.edgeca/config.yaml"

	os.Remove(filename)
	// initialize - read config - set defaults
	InitCLIConfiguration()

	// check defaults
	configGraphQLport := GetGraphQLPort()
	if configGraphQLport != 0 {
		t.Errorf("Default GraphQL port = %v, want 0", configGraphQLport)
	}

	configSDS := GetUseSDS()
	if configSDS != false {
		t.Errorf("Default SDS != false")
	}

	configToken, configURL, configZone := GetTPPCredentials()

	if configToken != "" || configURL != "" || configZone != "" {
		t.Errorf("Default TPP values %v,%v,%v, should be empty", configToken, configURL, configZone)
	}

	configTLSPort := GetServerTLSPort()
	if configTLSPort != 50025 {
		t.Errorf("configTLSPort is %v, expected %v", configTLSPort, 50025)
	}

	configPolicy := GetPolicyFile()
	if configPolicy != "" {
		t.Errorf("configPolicy = %v, should be empty", configPolicy)
	}

	configCACert, configCAKey := GetUserProvidedCACert()
	if configCACert != "" {
		t.Errorf("configCACert = %v, should be empty", configCACert)
	}

	if configCAKey != "" {
		t.Errorf("configCAKey = %v, should be empty", configCAKey)
	}

	configTLSHostname := GetServerTLSHost()
	defaultTLSCHostname := getDefaultTLSHost()

	if defaultTLSCHostname == "" {
		t.Errorf("defaultTLSCHostname is empty")
	}

	if configTLSHostname != defaultTLSCHostname {
		t.Errorf("configTLSHostname = %v, want %v", configTLSHostname, defaultTLSCHostname)
	}

	configDebugLogging := GetDebugLogLevel()
	if configDebugLogging != false {
		t.Errorf("configDebugLogging != false")
	}

	if UsingSelfSignedMode() == false || UsingIssuingCertMode() == true || UsingTPPPassthroughMode() == true || UsingUserCertMode() == true {
		t.Error("Invalid mode")
	}

	// set values
	SetGraphQLPort(1000)
	SetUseSDS(true)
	SetTPPCredentials("token", "url", "zone")
	SetServerTLSPort(2000)
	SetPolicyFile("policyfile")
	SetUserProvidedCACert("certfile", "keyfile")
	SetServerTLSHost("hostname")
	SetDebugLogLevel(true)

	// write config file
	WriteConfigFile()

	// set clear values
	SetGraphQLPort(0)
	SetUseSDS(false)
	SetTPPCredentials("", "", "")
	SetServerTLSPort(0)
	SetPolicyFile("")
	SetUserProvidedCACert("", "")
	SetServerTLSHost("")
	SetDebugLogLevel(false)

	// confirm they have been cleared
	if GetGraphQLPort() != 0 {
		t.Errorf("GetGraphQLPort() invalid")
	}

	if GetUseSDS() != false {
		t.Errorf("GetUseSDS() invalid ")
	}

	configToken, configURL, configZone = GetTPPCredentials()
	if configToken != "" || configURL != "" || configZone != "" {
		t.Errorf("TPP values invalid")
	}

	if GetServerTLSPort() != 0 {
		t.Errorf("GetServerTLSPort()invalid")
	}

	if GetPolicyFile() != "" {
		t.Errorf("GetPolicyFile() invalid")
	}

	configCACert, configCAKey = GetUserProvidedCACert()
	if configCACert != "" || configCAKey != "" {
		t.Errorf("configCACert and configCAKey invalid")
	}

	if GetServerTLSHost() != "" {
		t.Errorf("GetServerTLSHost invalid")
	}

	if GetDebugLogLevel() != false {
		t.Errorf("configDebugLogging invalid")
	}

	// read config file
	InitCLIConfiguration()
	// and remove it
	os.Remove(filename)

	// check that config values are correct
	if GetGraphQLPort() != 1000 {
		t.Errorf("GetGraphQLPort() invalid")
	}

	if GetUseSDS() != true {
		t.Errorf("GetUseSDS() invalid ")
	}

	configToken, configURL, configZone = GetTPPCredentials()
	if configToken != "token" || configURL != "url" || configZone != "zone" {
		t.Errorf("TPP values invalid")
	}

	if GetServerTLSPort() != 2000 {
		t.Errorf("GetServerTLSPort()invalid")
	}

	if GetPolicyFile() != "policyfile" {
		t.Errorf("GetPolicyFile() invalid")
	}

	configCACert, configCAKey = GetUserProvidedCACert()
	if configCACert != "certfile" || configCAKey != "keyfile" {
		t.Errorf("configCACert and configCAKey invalid")
	}

	if GetServerTLSHost() != "hostname" {
		t.Errorf("GetServerTLSHost invalid")
	}

	if GetDebugLogLevel() != true {
		t.Errorf("configDebugLogging invalid")
	}

	// Test the modes
	SetServerMode("self-signed")
	SetServerMode("user-provided")
	SetServerMode("issuing-certificate")
	SetServerMode("tpp-passthrough")
}
