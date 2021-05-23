/*******************************************************************************
 * Copyright 2021 EdgeSec OÜ
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
	"log"

	"github.com/edgesec-org/edgeca"
	"github.com/edgesec-org/edgeca/internal/cli/config"
	"github.com/edgesec-org/edgeca/internal/server"
	"github.com/edgesec-org/edgeca/internal/server/policies"
	"github.com/edgesec-org/edgeca/internal/server/state"
	"github.com/spf13/cobra"
)

var policy, defaultConfig, tppToken, tppURL, tppZone, caCert, caKey, serverTlsCertDir string
var tlsPort int

func init() {

	var serverCmd = &cobra.Command{
		Use:   "server",
		Short: "Run the EdgeCA server",
		Long: `The EdgeCA server can run in three modes
	
		Mode 1: Self-signed
		-------------------
		./edgeca server [-p policy_file]
		
		In this mode, EdgeCA starts up, creates a self-signed certificate 
		and optionally reads in an OPA policy file. 
		
		Mode 2:  Bring your own CA Certificate
		--------------------------
		./edgeca server [-p policy_file] -c certificate.pem -k key.pem
		
		In this mode, EdgeCA starts up, reads the CA certificate and key
		from the provided PEM files and optionally reads in an OPA policy file 
			
		Mode 3: Use TPP
		-------------------------------
		./edgeca server -t TPP-token
		
		EdgeCA gets an issuing certificate using the TPP token.
		It reads in the policy and default configuration from the TPP server 
	
	Note: In all three modes, the server writes certificates to the location
	specified by "tls-certs". These certificates are required by the edgeca client
	for encryption and authentication.
		`,
		Run: func(cmd *cobra.Command, args []string) {

			startEdgeCAServer()

		}}

	rootCmd.AddCommand(serverCmd)

	serverCmd.Flags().StringVarP(&policy, "policy", "p", "", "Policy File")

	serverCmd.Flags().StringVarP(&caCert, "ca-cert", "c", "", "Issuing Certificate File")
	serverCmd.Flags().StringVarP(&caKey, "ca-key", "k", "", "Issuing Certificate Key File")

	serverCmd.Flags().StringVarP(&tppToken, "token", "t", "", "TPP Token")
	serverCmd.Flags().StringVarP(&tppURL, "url", "u", "", "TPP URL")
	serverCmd.Flags().StringVarP(&tppZone, "zone", "z", "", "TPP Zone")

	serverTlsCertDir = config.GetDefaultTLSCertDir()
	serverCmd.Flags().StringVarP(&serverTlsCertDir, "tls-certs", "d", serverTlsCertDir, "Directory to write gRPC TLS Client certificates to")

	tlsPort = config.GetDefaultTLSPort()
	serverCmd.Flags().IntVarP(&tlsPort, "port", "", tlsPort, "Port number to use for this server")

}

// Execute the commands
func startEdgeCAServer() {
	fmt.Println("EdgeCA server " + edgeca.Version + " starting up")
	log.SetPrefix("edgeCA: ")

	if tppToken != "" || tppURL != "" || tppZone != "" {
		mode3UseTPP()
	} else if caCert != "" || caKey != "" {
		mode2BYOCert()

	} else {
		mode1SelfCert()
	}

	server.StartGrpcServer(tlsPort)

}

func mode1SelfCert() {

	if policy != "" {
		policies.LoadPolicy(policy)
	}

	log.Println("Mode 1 (Using self-signed issuing certificate and key)")
	state.InitState(serverTlsCertDir)

}

func mode2BYOCert() {
	if policy != "" {
		policies.LoadPolicy(policy)
	}

	log.Println("Mode 2 (Using provided issuing certificate and key).")
	err := state.InitStateUsingCerts(caCert, caKey, serverTlsCertDir)

	if err != nil {
		log.Fatalf("Error: %v", err.Error())
	}
}

func mode3UseTPP() {
	if caCert != "" || caKey != "" {
		log.Fatalln("Mode 3 (Using TPP). Error: If TPP-Token is specified, then CA-Cert and CA-Key can't also be specified. ")
	}
	if tppToken == "" || tppURL == "" || tppZone == "" {
		log.Fatalln("Mode 3 (Using TPP). Error: TPP Token, URL and Zone all need to be specified.")
	}

	if policy != "" || defaultConfig != "" {
		log.Println("Mode 3 (Using TPP). Warning: If TPP-Token is specified, policy file settings are ignored.")
	}

	log.Println("Mode 3 (Using TPP). Connecting using specified TPP token, URL and Zone")

	err := state.InitStateUsingTPP(tppURL, tppZone, tppToken, serverTlsCertDir)

	if err != nil {
		log.Fatalf("TPPLogin error: %v", err.Error())
	} else {
		log.Printf("TPPLogin OK")
	}
}