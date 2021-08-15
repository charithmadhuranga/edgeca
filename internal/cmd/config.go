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

package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/edgesec-org/edgeca/internal/config"
)

var configGraphQLport int
var configList, configPassthrough bool
var configToken, configURL, configZone string
var configSDS bool
var configTLSPort int
var configTLSHostname string
var configPolicy, configCACert, configCAKey, configTlsCertDir string
var configDebugLogging bool

var err error
var confconfigDir string

func init() {

	var configCmd = &cobra.Command{
		Use:   "config",
		Short: "Configure EdgeCA",
		Long: `Configuration settings
		 `,
		Args: cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {

		}}

	var listCmd = &cobra.Command{
		Use:   "list",
		Short: "List current settings",
		Long: `Shows the contents of the current configuration file
			`,
		Run: func(cmd *cobra.Command, args []string) {
			config.InitCLIConfiguration(confconfigDir)
			fmt.Println(config.GetConfigurationFileContents())
		}}
	listCmd.Flags().StringVarP(&confconfigDir, "confdir", "", confconfigDir, "Configuration Directory")

	var serverModeSelfSignedCmd = &cobra.Command{
		Use:   "self-signed",
		Short: "Self-signed mode",
		Long: `
Self-signed server mode
-------------------
./edgeca config self-signed [-p policy_file]
./edgeca server

In this mode, EdgeCA starts up, creates a self-signed certificate 
and optionally reads in an OPA policy file. 
		`,
		Run: func(cmd *cobra.Command, args []string) {
			//		config.InitCLIConfiguration(confconfigDir)
			//		config.SetServerMode(configMode)

			config.InitCLIConfiguration(confconfigDir)
			config.SetServerMode("self-signed")
			config.SetPolicyFile(configPolicy)
			config.WriteConfigFile()
		}}

	var serverModeUserProvided = &cobra.Command{
		Use:   "user-provided",
		Short: "User-provided CA certificate mode",
		Long: `
User-provided CA server mode
--------------------------
./edgeca config user-provided [-p policy_file] -c certificate.pem -k key.pem
./edgeca server

In this mode, EdgeCA starts up, reads the CA certificate and key
from the provided PEM files and optionally reads in an OPA policy file 
			`,
		Run: func(cmd *cobra.Command, args []string) {
			//		config.InitCLIConfiguration(confconfigDir)
			//		config.SetServerMode(configMode)

			config.InitCLIConfiguration(confconfigDir)
			config.SetServerMode("user-provided")
			config.SetPolicyFile(configPolicy)
			config.SetUserProvidedCACert(configCACert, configCAKey)
			config.WriteConfigFile()
		}}

	var serverModeIssuingCert = &cobra.Command{
		Use:   "issuing-certificate",
		Short: "issuing-certificate mode",
		Long: `
Issuing certificate mode
--------------------------
./edgeca config issuing-certificate -t TPP-token -u TPP-URL -z TPP-zone
./edgeca server

EdgeCA gets an issuing certificate using the TPP token.
It reads in the policy and default configuration from the TPP server
			`,
		Run: func(cmd *cobra.Command, args []string) {

			config.InitCLIConfiguration(confconfigDir)
			config.SetServerMode("issuing-certificate")
			config.SetTPPCredentials(configToken, configURL, configZone)
			config.WriteConfigFile()
		}}

	var serverModePassthrough = &cobra.Command{
		Use:   "tpp-passthrough",
		Short: "tpp-passthrough mode",
		Long: `
Use TPP to issue certificates
-------------------------------
./edgeca config tpp-passthrough -t TPP-token -u TPP-URL -z TPP-zone
./edgeca server

In this mode, EdgeCA does not use an issuing certificate and issues
no certificates locally. Instead it passes all requestes back to the back-end
using TPP.

				`,
		Run: func(cmd *cobra.Command, args []string) {

			config.InitCLIConfiguration(confconfigDir)
			config.SetServerMode("tpp-passthrough")
			config.SetTPPCredentials(configToken, configURL, configZone)
			config.WriteConfigFile()
		}}

	var grpcCmd = &cobra.Command{
		Use:   "grpc",
		Short: "gRPC settings",
		Long: `
			`,
		Run: func(cmd *cobra.Command, args []string) {
			config.InitCLIConfiguration(confconfigDir)
			config.SetServerTLSPort(configTLSPort)
			config.SetServerTLSHost(configTLSHostname)
			config.WriteConfigFile()
		}}

	var protocolCmd = &cobra.Command{
		Use:   "protocols",
		Short: "other protocol settings",
		Long: `
			`,
		Run: func(cmd *cobra.Command, args []string) {
			config.InitCLIConfiguration(confconfigDir)
			config.SetUseSDS(configSDS)
			config.SetGraphQLPort(configGraphQLport)
			config.WriteConfigFile()
		}}

	rootCmd.AddCommand(configCmd)
	configCmd.AddCommand(serverModeSelfSignedCmd)
	configCmd.AddCommand(listCmd)
	configCmd.AddCommand(serverModeUserProvided)
	configCmd.AddCommand(serverModeIssuingCert)
	configCmd.AddCommand(serverModePassthrough)
	configCmd.AddCommand(grpcCmd)
	configCmd.AddCommand(protocolCmd)

	confconfigDir = config.GetDefaultConfdir()

	serverModeSelfSignedCmd.Flags().StringVarP(&confconfigDir, "confdir", "", confconfigDir, "Configuration Directory")
	serverModeSelfSignedCmd.Flags().StringVarP(&configPolicy, "policy", "p", config.GetPolicyFile(), "OPA Policy Filename")

	serverModeUserProvided.Flags().StringVarP(&confconfigDir, "confdir", "", confconfigDir, "Configuration Directory")
	serverModeUserProvided.Flags().StringVarP(&configPolicy, "policy", "p", config.GetPolicyFile(), "OPA Policy Filename")
	serverModeUserProvided.Flags().StringVarP(&configCACert, "ca-cert", "c", configCACert, "User-provided CA Certificate File")
	serverModeUserProvided.Flags().StringVarP(&configCAKey, "ca-key", "k", configCAKey, "User-provided CA Private Key File")
	serverModeUserProvided.MarkFlagRequired("ca-key")
	serverModeUserProvided.MarkFlagRequired("ca-cert")

	serverModeIssuingCert.Flags().StringVarP(&confconfigDir, "confdir", "", confconfigDir, "Configuration Directory")
	serverModeIssuingCert.Flags().StringVarP(&configToken, "token", "t", configToken, "Venafi TPP Token")
	serverModeIssuingCert.Flags().StringVarP(&configURL, "url", "u", configURL, "Venafi TPP URL")
	serverModeIssuingCert.Flags().StringVarP(&configZone, "zone", "z", configZone, "Venafi TPP Zone")
	serverModeIssuingCert.MarkFlagRequired("token")
	serverModeIssuingCert.MarkFlagRequired("url")
	serverModeIssuingCert.MarkFlagRequired("zone")

	serverModePassthrough.Flags().StringVarP(&confconfigDir, "confdir", "", confconfigDir, "Configuration Directory")
	serverModePassthrough.Flags().StringVarP(&configToken, "token", "t", configToken, "Venafi TPP Token")
	serverModePassthrough.Flags().StringVarP(&configURL, "url", "u", configURL, "Venafi TPP URL")
	serverModePassthrough.Flags().StringVarP(&configZone, "zone", "z", configZone, "Venafi TPP Zone")
	serverModePassthrough.MarkFlagRequired("token")
	serverModePassthrough.MarkFlagRequired("url")
	serverModePassthrough.MarkFlagRequired("zone")

	grpcCmd.Flags().StringVarP(&confconfigDir, "confdir", "", confconfigDir, "Configuration Directory")
	grpcCmd.Flags().IntVarP(&configTLSPort, "port", "", 50025, "TCP/IP port to use for EdgeCA gRPC server")
	grpcCmd.Flags().StringVarP(&configTLSHostname, "server", "", config.GetDefaultTLSHost(), "EdgeCA gRPC server hostname")
	grpcCmd.MarkFlagRequired("port")
	grpcCmd.MarkFlagRequired("server")

	protocolCmd.Flags().StringVarP(&confconfigDir, "confdir", "", confconfigDir, "Configuration Directory")
	protocolCmd.Flags().IntVarP(&configGraphQLport, "graphql-port", "", 0, "If set, enable GraphQL server on this TCP/IP port")
	protocolCmd.Flags().BoolVarP(&configSDS, "enable-sds", "", false, "Enable experimental Envoy SDS support")
	protocolCmd.MarkFlagRequired("enable-sds")
	protocolCmd.MarkFlagRequired("graphql-port")

}
