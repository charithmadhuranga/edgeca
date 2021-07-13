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
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"log"
	"strconv"
	"time"

	"github.com/edgesec-org/edgeca/internal/config"
	certs "github.com/edgesec-org/edgeca/internal/issuer"
	internalgrpc "github.com/edgesec-org/edgeca/internal/server/grpcimpl"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

var csrFile, certFileName, certkeyFileName, certtlsCertDir, tlsHostName string
var certTLSPort int

func init() {
	var gencsr = &cobra.Command{
		Use:   "gencert",
		Short: "Create a Certificate",
		Run: func(cmd *cobra.Command, args []string) {

			grpcGenerateCertificate()

		}}

	rootCmd.AddCommand(gencsr)

	gencsr.Flags().StringVarP(&csrFile, "csr", "i", "", "Input CSR file")
	gencsr.Flags().StringVarP(&certFileName, "cert", "o", "", "Output Certificate file")
	gencsr.Flags().StringVarP(&certkeyFileName, "key", "k", "", "Output Private Key file")
	certtlsCertDir = config.GetDefaultTLSCertDir()
	gencsr.Flags().StringVarP(&certtlsCertDir, "tls-certs", "d", certtlsCertDir, "Location of certs for gRPC authentication")
	tlsHostName = config.GetDefaultTLSHost()
	gencsr.Flags().StringVarP(&tlsHostName, "server", "", tlsHostName, "EdgeCA gRPC server name")
	certTLSPort = config.GetDefaultTLSPort()
	gencsr.Flags().IntVarP(&certTLSPort, "port", "", certTLSPort, "TLS port of gRPC server")

	gencsr.MarkFlagRequired("csr")

}

func getcsr() (csr string) {
	content, err := ioutil.ReadFile(csrFile)
	if err != nil {
		log.Fatalf("could not read file %s: %v", csrFile, err)
	}

	// Convert []byte to string and print to screen
	csr = string(content)
	return
}

func grpcConnect(tlsCertDir, host string, port int) (*grpc.ClientConn, internalgrpc.CAClient) {

	log.Println("Loading TLS certificates from " + tlsCertDir)

	certPool, err := certs.LoadCAServerCert(tlsCertDir + "/CA.pem")
	if err != nil {
		log.Fatalf("Could not load CA certificate for TLS connection: %s", err)
	}

	clientCert, err := tls.LoadX509KeyPair(tlsCertDir+"/edgeca-client-cert.pem", tlsCertDir+"/edgeca-client-key.pem")
	if err != nil {
		log.Fatalf("Could not load TLS client certificate and key: %s", err)
	}

	config := &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      certPool,
	}

	creds := credentials.NewTLS(config)

	//	log.Println("Connecting to GRPC server,", creds)
	conn, err := grpc.Dial(host+":"+strconv.Itoa(port), grpc.WithTransportCredentials(creds)) //, grpc.WithBlock()

	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	c := internalgrpc.NewCAClient(conn)

	return conn, c
}

func grpcGenerateCertificate() {
	csr := getcsr()
	log.Println("Connecting to edgeca server at " + tlsHostName + " to sign certificate")

	conn, c := grpcConnect(certtlsCertDir, tlsHostName, certTLSPort)
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	csrReply, err := c.GenerateCertificate(ctx, &internalgrpc.CertificateRequest{
		Csr: csr,
	})

	if err != nil {
		log.Fatalf("could not get: %v", err)
	}

	certificate := csrReply.GetCertificate()
	key := csrReply.GetPrivateKey()

	if certFileName != "" {
		err = ioutil.WriteFile(certFileName, []byte(certificate), 0644)
		if err != nil {
			log.Fatalf("Error writing Certificate to %s: %v", certFileName, err)
		} else {
			log.Printf("Wrote Certificate to %s", certFileName)
		}

	} else {
		fmt.Println(certificate)
	}

	if certkeyFileName != "" {
		err = ioutil.WriteFile(certkeyFileName, []byte(key), 0644)
		if err != nil {
			log.Fatalf("Error writing key to %s: %v", certkeyFileName, err)
		} else {
			log.Printf("Wrote key to %s", certkeyFileName)
		}

	} else {
		fmt.Println(key)
	}

}
