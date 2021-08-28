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

package state

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io/ioutil"
	"os"

	log "github.com/sirupsen/logrus"

	certs "github.com/edgesec-org/edgeca/internal/issuer"
	"github.com/edgesec-org/edgeca/internal/policies"
	"github.com/edgesec-org/edgeca/internal/server/tpp"
)

const mode1UseSelfSigned = 1
const mode2UseBYOCert = 2
const mode3UseTPP = 3
const mode4TPPPassthrough = 4

type state struct {
	rootCACert     *x509.Certificate
	rootCAKey      *rsa.PrivateKey
	rootCAPAMCert  []byte
	subCACert      *x509.Certificate
	subCAKey       *rsa.PrivateKey
	subCAPEMCert   []byte
	tppURL         string
	tppZone        string
	tppToken       string
	organization   string
	tlsCertificate *tls.Certificate
	passthrough    bool
	mode           int
}

var serverState state

func UsingPassthrough() bool {
	return serverState.passthrough
}

func GetSubCACert() *x509.Certificate {
	return serverState.subCACert
}

func GetSubCAKey() *rsa.PrivateKey {
	return serverState.subCAKey
}

func GetSubCAPEMCert() []byte {
	return serverState.subCAPEMCert
}

func GetRootCACert() []byte {
	return serverState.rootCAPAMCert
}

func GetServerTLSCert() *tls.Certificate {
	return serverState.tlsCertificate
}

func GetStateDescription() (result string) {
	switch serverState.mode {

	case mode1UseSelfSigned:
		result = "Local Self Signed CA (" + serverState.subCACert.Subject.CommonName + "/" + serverState.subCACert.Issuer.CommonName + ")"
	case mode2UseBYOCert:
		result = "User Provided Root CA certificate (" + serverState.subCACert.Subject.CommonName + "/" + serverState.subCACert.Issuer.CommonName + ")"
	case mode3UseTPP:
		result = "Venafi TPP (" + serverState.subCACert.Subject.CommonName + "/" + serverState.subCACert.Issuer.CommonName + ")"
	case mode4TPPPassthrough:
		result = "Venafi TPP passthrough"
	}
	return
}

// InitState initializes the in-memory state
func InitState(tlsCertDir string) {
	var err error
	serverState.mode = mode1UseSelfSigned

	serverState.organization = "EdgeCA"
	serverState.rootCACert, serverState.rootCAPAMCert, serverState.rootCAKey, err = certs.GenerateSelfSignedRootCACertAndKey()
	if err != nil {
		log.Fatalln("Could not initialize Root CA: ", err)
	}
	serverState.subCACert, serverState.subCAPEMCert, serverState.subCAKey, err = certs.GenerateSelfSignedSubCACertAndKey(serverState.rootCACert, serverState.rootCAKey)
	if err != nil {
		log.Fatalln("Could not initialize Sub CA: ", err)
	}

	setupTLSConnection(tlsCertDir)

}

func InitStateUsingCerts(caCert, caKey, tlsCertDir string) error {

	serverState.mode = mode2UseBYOCert

	pemRootCACert, err := ioutil.ReadFile(caCert)
	if err != nil {
		return err
	}
	pemKey, err := ioutil.ReadFile(caKey)
	if err != nil {
		return err
	}

	rsaRootKey, err := certs.PemToRSAPrivateKey([]byte(pemKey))

	if err != nil {
		log.Fatalln("Could not initialize Root CA: ", err)
	}
	rootCert, err := certs.PemToCert(pemRootCACert)

	if err != nil {
		log.Fatalln("Could not initialize Root CA: ", err)
	}
	serverState.rootCACert = rootCert
	serverState.rootCAPAMCert = pemRootCACert
	serverState.rootCAKey = rsaRootKey

	serverState.subCACert, serverState.subCAPEMCert, serverState.subCAKey, err = certs.GenerateSelfSignedSubCACertAndKey(serverState.rootCACert, serverState.rootCAKey)
	if err != nil {
		log.Fatalln("Could not initialize Sub CA: ", err)
	}

	setupTLSConnection(tlsCertDir)

	return nil

}

func getDefaultTLSHost() string {
	hostName, _ := os.Hostname()
	return hostName
}

func setupTLSConnection(certDir string) {
	var err error
	hostName := getDefaultTLSHost()

	serverState.tlsCertificate, err = certs.GenerateTLSServerCert(hostName, GetSubCACert(), GetSubCAKey())
	if err != nil {
		log.Fatalln("Could not initialize TLS: ", err)
	}

	_, err = certs.GenerateTLSClientCert(hostName, GetSubCACert(), GetSubCAKey(), certDir+"/edgeca-client-cert.pem", certDir+"/edgeca-client-key.pem")

	if err != nil {
		log.Fatalln("Could not create TLS client cert: ", err)
	}

	filename := certDir + "/CA.pem"
	log.Infoln("Writing Root CA Certificate to ", filename)
	cert := GetRootCACert()
	subCA := GetSubCAPEMCert()
	certs := make([]byte, len(cert)+len(subCA))
	copy(certs, cert)
	copy(certs[len(cert):], subCA)

	if filename != "" {
		err := ioutil.WriteFile(filename, certs, 0644)
		if err != nil {
			log.Fatalf("Error writing output to %s: %v", filename, err)
		}
	}

}

func InitStateUsingTPP(url, zone, token, certDir string) (err error) {
	serverState.mode = mode3UseTPP
	serverState.tppToken = token
	serverState.tppURL = url
	serverState.tppZone = zone
	serverState.passthrough = false

	serverState.rootCACert, serverState.rootCAPAMCert, serverState.subCACert, serverState.subCAPEMCert, serverState.subCAKey, err =
		tpp.GenerateTPPRootCACertAndKey(url, zone, token)
	if err != nil {
		log.Debugln("Error: Could not initialize Root CA: ", err)
		return errors.New("TPP Error:" + err.Error())
	}

	log.Debugln("Root CA Certificate now: ", serverState.rootCACert.Subject.CommonName)
	log.Debugln("Sub CA Certificate now: ", serverState.subCACert.Subject.CommonName)

	defaultValues, restrictions, err := tpp.TPPGetPolicy(url, zone, token)

	log.Debugln("TPP Default values from policy:", defaultValues)

	log.Debugln("Reading enforced locked values from TPP policy:", restrictions)
	policies.ApplyTPPValues(defaultValues, restrictions)

	setupTLSConnection(certDir)

	return nil
}

func InitStateUsingTPPPassthrough(url, zone, token, certDir string) (err error) {
	serverState.mode = mode4TPPPassthrough
	serverState.tppToken = token
	serverState.tppURL = url
	serverState.tppZone = zone
	serverState.passthrough = true

	log.Debugln("Initializing EdgeCA in pass-through mode. All requests will be forwarded using TPP")

	// the mTLS connection to our client still uses a self-signed certificate...
	InitState(certDir)

	defaultValues, restrictions, err := tpp.TPPGetPolicy(url, zone, token)

	log.Debugln("TPP Default values from policy:", defaultValues)

	log.Debugln("Reading enforced locked values from TPP policy:", restrictions)
	policies.ApplyTPPValues(defaultValues, restrictions)

	return nil
}

func GenerateCertificateUsingTPP(subject pkix.Name) (pemChain string, pemCertificate string, pemPrivateKey string, err error) {
	return tpp.TPPGenerateCertificateChainAndKey(serverState.tppURL, serverState.tppZone, serverState.tppToken, subject)

}
