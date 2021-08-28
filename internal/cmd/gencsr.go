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
	"context"
	"fmt"
	"io/ioutil"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/edgesec-org/edgeca"
	"github.com/edgesec-org/edgeca/internal/config"
	certs "github.com/edgesec-org/edgeca/internal/issuer"
	internalgrpc "github.com/edgesec-org/edgeca/internal/server/grpcimpl"

	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"

	"github.com/spf13/cobra"
)

var commonName, organization, organizationalUnit, locality, province, country, keyFileName, csrFileName string
var refresh bool

func init() {
	var gencsr = &cobra.Command{
		Use:   "gencsr",
		Short: "Create a CSR",
		Run: func(cmd *cobra.Command, args []string) {

			generateCSR()

		}}

	rootCmd.AddCommand(gencsr)

	gencsr.Flags().StringVarP(&commonName, "cn", "", "", "Common Name (required)")
	gencsr.MarkFlagRequired("cn")
	gencsr.Flags().StringVarP(&organization, "organization", "o", "", "Organization")
	gencsr.Flags().StringVarP(&organizationalUnit, "ou", "", "", "Organizational Unit")
	gencsr.Flags().StringVarP(&locality, "locality", "l", "", "Locality")
	gencsr.Flags().StringVarP(&province, "st", "", "", "State/Province")
	gencsr.Flags().StringVarP(&country, "country", "c", "", "Country")
	gencsr.Flags().StringVarP(&keyFileName, "key", "", "", "Output file for private key used to sign CSR")
	gencsr.Flags().StringVarP(&csrFileName, "csr", "", "", "Output file for CSR")
	gencsr.Flags().BoolVarP(&refresh, "refresh", "r", false, "Refresh the list of default values from the current policy")

	configDir = config.GetDefaultConfdir()
	gencsr.Flags().StringVarP(&configDir, "confdir", "", configDir, "Configuration Directory")

}

func generateCSR() {

	config.InitCLIConfiguration(configDir)

	if config.GetDebugLogLevel() {
		log.SetLevel(log.DebugLevel)
		log.Debugln("EdgeCA v" + edgeca.Version + " debug logging enabled")

	}

	// only use gRPC if --refresh is set
	if refresh {
		server := config.GetServerTLSHost()
		mtlsDir := getTLSCertDir()
		csrTLSPort := config.GetServerTLSPort()

		log.Debugln("Connecting to edgeca server at " + server + " to refresh policy information")

		conn, c := grpcConnect(mtlsDir, server, csrTLSPort)
		defer conn.Close()
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()

		policyReply, err := c.RequestPolicy(ctx, &internalgrpc.PolicyRequest{})
		if err != nil {
			log.Fatalf("could not get: %v", err)
		}

		o := policyReply.GetDefaultOrganization()
		ou := policyReply.GetDefaultOrganizationalUnit()
		p := policyReply.GetDefaultProvince()
		l := policyReply.GetDefaultLocality()
		country := policyReply.GetDefaultCountry()
		config.SetCSRConfiguration(o, ou, country, p, l)
	}

	// then generate the CSR

	csrBytes, keyBytes, err := generatePemCSR()

	if csrFileName != "" {
		err = ioutil.WriteFile(csrFileName, csrBytes, 0644)
		if err != nil {
			log.Fatalf("Error writing CSR to %s: %v", csrFileName, err)
		}
	} else {
		fmt.Println(string(csrBytes))
	}

	if keyFileName != "" {
		err = ioutil.WriteFile(keyFileName, keyBytes, 0644)
		if err != nil {
			log.Fatalf("Error writing key to %s: %v", keyFileName, err)
		}
	} else {
		fmt.Println(string(keyBytes))
	}

}

// GeneratePemCSR generates a certificate
func generatePemCSR() (csrBytes []byte, privatekeyBytes []byte, err error) {
	//	var oidEmailAddress = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}

	//	emailAddress := "test@example.com"
	subj := pkix.Name{
		CommonName: commonName,
	}

	if organization == "" {
		organization = config.GetDefaultOrganization()
	}
	if organization != "" {
		subj.Organization = []string{organization}
	}

	if organizationalUnit == "" {
		organizationalUnit = config.GetDefaultOrganizationalUnit()
	}
	if organizationalUnit != "" {
		subj.OrganizationalUnit = []string{organizationalUnit}
	}

	if locality == "" {
		locality = config.GetDefaultLocality()
	}
	if locality != "" {
		subj.Locality = []string{locality}
	}

	if province == "" {
		province = config.GetDefaultProvince()
	}
	if province != "" {
		subj.Province = []string{province}
	}
	if country == "" {
		country = config.GetDefaultCountry()
	}
	if country != "" {
		subj.Country = []string{country}
	}

	privateRSAKey, err := certs.GenerateRSAKey()

	derBytes, err := certs.GenerateCSR(subj, privateRSAKey)

	csrBytes = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: derBytes})
	privatekeyBytes = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateRSAKey)})
	log.Debugln("Generated CSR for [", subj, "]")
	return csrBytes, privatekeyBytes, err
}
