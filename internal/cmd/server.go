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
	"os"

	log "github.com/sirupsen/logrus"

	"github.com/edgesec-org/edgeca"
	"github.com/edgesec-org/edgeca/internal/config"
	"github.com/edgesec-org/edgeca/internal/policies"
	"github.com/edgesec-org/edgeca/internal/server"
	"github.com/edgesec-org/edgeca/internal/state"
	"github.com/spf13/cobra"
)

var configDir string

func init() {

	var serverCmd = &cobra.Command{
		Use:   "server",
		Short: "Run the EdgeCA server",
		Long: `The EdgeCA server can run in four modes
	

	
	Note: The server uses mTLS to communicate with the edgeca CLI. It does so using 
	client certificates written to the location specified by "grpc-server/tls-certificates". 
	If the CLI client is used on a different computer, then these certificates need to be
	copied across for the client to use.
		`,
		Run: func(cmd *cobra.Command, args []string) {

			startEdgeCAServer()

		}}

	rootCmd.AddCommand(serverCmd)
	configDir = config.GetDefaultConfdir()
	serverCmd.Flags().StringVarP(&configDir, "confdir", "", configDir, "Configuration Directory")

}

// Execute the commands
func startEdgeCAServer() {
	fmt.Println("EdgeCA server " + edgeca.Version + " starting up")

	config.InitCLIConfiguration(configDir)

	if config.GetDebugLogLevel() {
		log.SetLevel(log.DebugLevel)
		log.Debugln("Debug logging enabled")

	}

	if config.UsingSelfSignedMode() {

		log.Infoln("Server mode: self-signed")
		policy := config.GetPolicyFile()
		serverTlsCertDir := getTLSCertDir()
		if policy != "" {
			policies.LoadPolicy(policy)
		}
		state.InitState(serverTlsCertDir)

	} else if config.UsingUserCertMode() {

		log.Infoln("Server mode: user-provided CA certificate and private key")

		policy := config.GetPolicyFile()
		serverTlsCertDir := getTLSCertDir()
		caCert, caKey := config.GetUserProvidedCACert()
		if policy != "" {
			policies.LoadPolicy(policy)
		}
		err := state.InitStateUsingCerts(caCert, caKey, serverTlsCertDir)
		if err != nil {
			log.Fatalf("Error: %v", err.Error())
		}

	} else if config.UsingIssuingCertMode() {

		log.Infoln("Server mode: Using TPP")

		policy := config.GetPolicyFile()
		serverTlsCertDir := getTLSCertDir()
		caCert, caKey := config.GetUserProvidedCACert()
		tppToken, tppURL, tppZone := config.GetTPPCredentials()

		if caCert != "" || caKey != "" {
			log.Warnln("Ignoring user-provided CA-Cert and CA-Key from configuration")
		}
		if tppToken == "" || tppURL == "" || tppZone == "" {
			log.Fatalln("Error: TPP Token, URL and Zone all need to be specified.")
		}

		if policy != "" {
			log.Warnln("Ignoring OPA policy file from configuration - using TPP policy information")
		}

		err := state.InitStateUsingTPP(tppURL, tppZone, tppToken, serverTlsCertDir)

		if err != nil {
			log.Fatalf("TPPLogin error: %v", err.Error())
		} else {
			log.Infoln("TPPLogin OK")
		}
	} else if config.UsingTPPPassthroughMode() {

		log.Infoln("Server mode: TPP/Passthrough. All requests will be forwarded using TPP")

		tppToken, tppURL, tppZone := config.GetTPPCredentials()

		caCert, caKey := config.GetUserProvidedCACert()
		policy := config.GetPolicyFile()
		serverTlsCertDir := getTLSCertDir()

		if caCert != "" || caKey != "" {
			log.Warnln("Ignoring user-provided CA-Cert and CA-Key from configuration")
		}

		if tppToken == "" || tppURL == "" || tppZone == "" {
			log.Fatalln("Error: TPP Token, URL and Zone all need to be specified.")
		}

		if policy != "" {
			log.Warnln("Ignoring OPA policy file from configuration - using TPP policy information")
		}

		err := state.InitStateUsingTPPPassthrough(tppURL, tppZone, tppToken, serverTlsCertDir)
		if err != nil {
			log.Fatalf("TPPLogin error: %v", err.Error())
		} else {
			log.Infoln("TPPLogin OK")
		}
	} else {
		log.Fatalf("No valid server mode enabled in configuration")
	}

	graphQLPort := config.GetGraphQLPort()
	useSDS := config.GetUseSDS()
	tlsPort := config.GetServerTLSPort()

	if graphQLPort > 0 {
		log.Infof("GraphQL server started on port %d (gRPC disabled)", graphQLPort)
		server.StartGraphqlServer(graphQLPort)
	} else {
		log.Infof("GraphQL server disabled")
		if useSDS {
			log.Infof("SDS server enabled")
		} else {
			log.Infof("SDS server disabled")
		}
		log.Infof("gRPC server started on port %d", tlsPort)

		server.StartGrpcServer(tlsPort, useSDS)
	}

}

func getTLSCertDir() string {

	defaultTLSCertDir := configDir + "/certs"

	if _, err := os.Stat(defaultTLSCertDir); os.IsNotExist(err) {
		_ = os.Mkdir(defaultTLSCertDir, 0755)
	} else {
	}

	return defaultTLSCertDir
}
