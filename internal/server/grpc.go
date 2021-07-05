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

package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"log"
	"net"
	"strconv"

	"github.com/edgesec-org/edgeca/internal/issuer"
	"github.com/edgesec-org/edgeca/internal/server/grpcimpl"
	"github.com/edgesec-org/edgeca/internal/server/sds"
	"github.com/edgesec-org/edgeca/internal/state"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/edgesec-org/edgeca/internal/policies"
)

// server is used to implement grpc.CAServer.
type server struct {
	grpcimpl.UnimplementedCAServer
}

func (s *server) RequestPolicy(ctx context.Context, request *grpcimpl.PolicyRequest) (*grpcimpl.PolicyReply, error) {
	log.Println("Got request for Policy Information")

	policyStr := string(policies.GetCurrentPolicy())
	defaultO, defaultOU, defaultC, defaultST, defaultL := policies.GetDefaultValues()

	log.Println("DefaultOrganization:", defaultO)
	return &grpcimpl.PolicyReply{
		Policy:                    policyStr,
		DefaultOrganization:       defaultO,
		DefaultOrganizationalUnit: defaultOU,
		DefaultProvince:           defaultST,
		DefaultLocality:           defaultL,
		DefaultCountry:            defaultC,
	}, nil

}

func (s *server) GenerateCertificate(ctx context.Context, request *grpcimpl.CertificateRequest) (reply *grpcimpl.CertificateReply, err error) {
	var pemCertificate, pemPrivateKey string

	csrByteString := request.GetCsr()

	err = policies.CheckPolicy(csrByteString)
	if err != nil {
		log.Printf("Policy result: %v", err)
		return nil, err
	}
	subject := issuer.GetSubjectFromCSR(csrByteString)

	if state.UsingPassthrough() {

		_, pemCertificate, pemPrivateKey, err = state.GenerateCertificateUsingTPP(subject)

	} else {
		var bCertificate, bPrivateKey []byte
		bCertificate, bPrivateKey, _, err = issuer.GenerateCertificateUsingX509Subject(subject, state.GetSubCACert(), state.GetSubCAKey())
		pemCertificate = string(bCertificate)
		pemPrivateKey = string(bPrivateKey)

	}

	return &grpcimpl.CertificateReply{Certificate: /*string(state.GetSubCAPEMCert()) +*/ pemCertificate, PrivateKey: pemPrivateKey}, err
}

//StartGrpcServer starts up the gRPC server
func StartGrpcServer(port int, useSDS bool) {

	certPool := x509.NewCertPool()
	cacert := state.GetRootCACert()
	subCA := state.GetSubCAPEMCert()
	certs := make([]byte, len(cacert)+len(subCA))
	copy(certs, cacert)
	copy(certs[len(cacert):], subCA)

	if !certPool.AppendCertsFromPEM(certs) {
		log.Fatalf("Could not add CA certificates to TLS Cert Pool")
	}

	cert := state.GetServerTLSCert()
	creds := credentials.NewTLS(
		&tls.Config{
			Certificates: []tls.Certificate{*cert},
			ClientAuth:   tls.RequireAndVerifyClientCert,
			ClientCAs:    certPool,
		})

	lis, err := net.Listen("tcp", ":"+strconv.Itoa(port))
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	s := grpc.NewServer(
		grpc.Creds(creds),
	)

	if useSDS {
		log.Println("Enabling SDS support")
		sds.InjectSDSServer(s)
	}

	log.Println("Starting gRPC CA server on port", port)

	grpcimpl.RegisterCAServer(s, &server{})
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}

}
