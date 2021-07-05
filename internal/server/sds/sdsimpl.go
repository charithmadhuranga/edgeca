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

package sds

import (
	"context"
	"crypto/x509/pkix"
	"log"
	"time"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	tls "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	secretservice "github.com/envoyproxy/go-control-plane/envoy/service/secret/v3"
	"github.com/gogo/protobuf/proto"
	"github.com/golang/protobuf/ptypes"
	"github.com/golang/protobuf/ptypes/any"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	certs "github.com/edgesec-org/edgeca/internal/issuer"
	"github.com/edgesec-org/edgeca/internal/state"
)

const (
	grpcMaxConcurrentStreams = 1000000
)

type Stream interface {
	grpc.ServerStream
	Send(*discovery.DiscoveryResponse) error
	Recv() (*discovery.DiscoveryRequest, error)
}

type server struct {
	ctx         context.Context
	streamCount int64
}

func (s *server) StreamSecrets(stream secretservice.SecretDiscoveryService_StreamSecretsServer) error {

	// a channel for receiving incoming requests
	reqCh := make(chan *discovery.DiscoveryRequest)
	go func() {
		defer close(reqCh)
		for {
			req, err := stream.Recv()
			if err != nil {
				return
			}
			select {
			case reqCh <- req:

			case <-stream.Context().Done():
				return
			case <-s.ctx.Done():
				return
			}
		}
	}()

	for {
		select {
		case <-s.ctx.Done():
			return nil
		case req, more := <-reqCh:
			// input stream ended or errored out
			if !more {
				return nil
			}
			if req == nil {
				return status.Errorf(codes.Unavailable, "empty request")
			}

			// nonces can be reused across streams; we verify nonce only if nonce is not initialized
			//nonce := req.GetResponseNonce()

			hostname := req.GetResourceNames()[0]
			resp, _ := getResponse(hostname)
			s.streamCount++
			//		log.Printf("SDS: Processing request for certificates for %v", req.GetResourceNames())
			stream.Send(resp)

		}
		time.Sleep(1000 * time.Millisecond)

	}

}

func (s *server) FetchSecrets(ctx context.Context, req *discovery.DiscoveryRequest) (*discovery.DiscoveryResponse, error) {

	log.Println("SDS: FetchSecrets")

	return nil, nil
}

func (s *server) DeltaSecrets(stream secretservice.SecretDiscoveryService_DeltaSecretsServer) error {
	log.Println("SDS: DeltaSecrets")

	return nil
}

type Resource interface {
	proto.Message
}

type secret struct {
	certificate string
	key         string
}

var secrets map[string]secret

func InjectSDSServer(grpcServer *grpc.Server) {

	secrets = make(map[string]secret)

	context := context.Background()
	srv := &server{
		ctx:         context,
		streamCount: 0,
	}
	secretservice.RegisterSecretDiscoveryServiceServer(grpcServer, secretservice.SecretDiscoveryServiceServer(srv))

}

func generateSDSCertificate(host string) (pemCert, pemKey string, err error) {
	var pemCertificateString, pemPrivateKeyString string

	if state.UsingPassthrough() {
		log.Println("SDS: Using TPP to sign certificate for " + host)

		_, pemCertificateString, pemPrivateKeyString, err = state.GenerateCertificateUsingTPP(pkix.Name{CommonName: host})

	} else {
		log.Println("SDS: Using EdgeCA issuing certificate to sign certificate for " + host)

		var pemCertificate, pemPrivateKey []byte
		pemCertificate, pemPrivateKey, _, err = certs.GeneratePemCertificate(pkix.Name{CommonName: host}, state.GetSubCACert(), state.GetSubCAKey())
		pemCertificateString = string(pemCertificate)
		pemPrivateKeyString = string(pemPrivateKey)
	}

	return pemCertificateString, pemPrivateKeyString, err
}

func getResponse(host string) (*discovery.DiscoveryResponse, error) {

	var marshaledResources []*any.Any

	secret := makeSecret(host)
	pbst, err := ptypes.MarshalAny(secret)
	if err != nil {
		panic(err)
	}

	marshaledResources = make([]*any.Any, 1)
	marshaledResources[0] = pbst

	result := &discovery.DiscoveryResponse{
		VersionInfo: "1",
		Resources:   marshaledResources,
		TypeUrl:     "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.Secret",
	}
	return result, nil

}

func makeSecret(host string) *tls.Secret {
	var pemCert, pemKey string

	s, found := secrets[host]
	if found {
		log.Println("SDS: returning cached certificate for " + host)
		pemCert = s.certificate
		pemKey = s.key
	} else {
		log.Println("SDS: Caching certificate for " + host)
		pemCert, pemKey, _ = generateSDSCertificate(host)
		secrets[host] = secret{certificate: pemCert, key: pemKey}
	}

	certificate := &tls.Secret_TlsCertificate{}

	certificate.TlsCertificate = &tls.TlsCertificate{}
	certificate.TlsCertificate.CertificateChain = &core.DataSource{}
	certificate.TlsCertificate.PrivateKey = &core.DataSource{}

	certificate.TlsCertificate.CertificateChain.Specifier = &core.DataSource_InlineString{
		InlineString: pemCert,
	}

	certificate.TlsCertificate.PrivateKey.Specifier = &core.DataSource_InlineString{
		InlineString: pemKey,
	}

	result := &tls.Secret{}
	result.Name = host
	result.Type = certificate

	return result
}
