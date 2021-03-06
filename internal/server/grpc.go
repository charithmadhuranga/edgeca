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

package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"strconv"

	log "github.com/sirupsen/logrus"

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
	log.Debugln("Got request for Policy Information")

	policyStr := string(policies.GetCurrentPolicy())
	defaultO, defaultOU, defaultC, defaultST, defaultL := policies.GetDefaultValues()

	log.Debugln("DefaultOrganization:", defaultO)
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
		log.Debugf("Policy result: %v", err)
		return nil, err
	}
	subject := issuer.GetSubjectFromCSR(csrByteString)

	if state.UsingPassthrough() {

		_, pemCertificate, pemPrivateKey, err = state.GenerateCertificateUsingTPP(subject)

	} else {
		var bCertificate, bPrivateKey []byte

		log.Infoln("gRPC request: certificate for " + subject.CommonName + " from issuer: " + state.GetStateDescription())

		bCertificate, bPrivateKey, _, err = issuer.GenerateCertificateUsingX509Subject(subject)
		pemCertificate = string(bCertificate)
		pemPrivateKey = string(bPrivateKey)

	}
	// from https://datatracker.ietf.org/doc/html/rfc4346#section-7.4.1.2 and https://datatracker.ietf.org/doc/html/rfc8446#section-4.4.2
	/*
		certificate_list
			This is a sequence (chain) of X.509v3 certificates.  The sender's
			certificate must come first in the list.  Each following
			certificate must directly certify the one preceding it.  Because
			certificate validation requires that root keys be distributed
			independently, the self-signed certificate that specifies the root
			certificate authority may optionally be omitted from the chain,
			under the assumption that the remote end must already possess it
			in order to validate it in any case.
	*/

	return &grpcimpl.CertificateReply{Certificate: pemCertificate + string(state.GetSubCAPEMCert()), PrivateKey: pemPrivateKey}, err
}

//StartGrpcServer starts up the gRPC server
func StartGrpcServer(port int, useSDS bool) {

	certPool := x509.NewCertPool()
	cacert := state.GetRootCAPEMCert()
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
		log.Infof("Enabling SDS support")
		sds.InjectSDSServer(s)
	}

	log.Infof("Starting gRPC CA server on port %d", port)

	grpcimpl.RegisterCAServer(s, &server{})
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}

}
