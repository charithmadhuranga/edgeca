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

package issuer

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"

	"github.com/edgesec-org/edgeca/internal/config"
	log "github.com/sirupsen/logrus"
)

var serialNumber big.Int

var rootCACert *x509.Certificate
var rootCAPrivateKey *rsa.PrivateKey
var rootCAPEMCert []byte

var subCACert *x509.Certificate
var subCAPrivateKey *rsa.PrivateKey
var subCAPEMCert []byte

func GetSubCAPEMCert() []byte {
	return subCAPEMCert
}

func GetRootCAPEMCert() []byte {
	return rootCAPEMCert
}

func SetRootCA(rootCert *x509.Certificate, pemRootCACert []byte, rsaRootKey *rsa.PrivateKey) {
	rootCACert = rootCert
	rootCAPEMCert = pemRootCACert
	rootCAPrivateKey = rsaRootKey

}

func SetSubCA(rootCert *x509.Certificate, pemRootCACert []byte, rsaRootKey *rsa.PrivateKey) {
	subCACert = rootCert
	subCAPEMCert = pemRootCACert
	subCAPrivateKey = rsaRootKey

}

func GenerateCertificateUsingX509Subject(subject pkix.Name) (certificate []byte, key []byte, expiryString string, err error) {

	//	err = policies.CheckPolicy(csrByteString)

	//	if err != nil {
	//		log.Debugf("Policy result: %v", err)
	//		return nil, nil, err
	//	}

	pemCertificate, pemPrivateKey, expiryString, err := GeneratePemCertificate(subject, true)
	return pemCertificate, pemPrivateKey, expiryString, err
}

func GenerateCertificateUsingX509SubjectOptionalValues(commonName string, o, ou, l, p, c *string,
	subCACert *x509.Certificate, casubCAKeyCert *rsa.PrivateKey) (certificate []byte, key []byte, expiryString string, err error) {

	var organization, organizationalUnit, locality, province, country string

	if o != nil {
		organization = *o
	}
	if ou != nil {
		organizationalUnit = *ou
	}
	if l != nil {
		locality = *l
	}
	if p != nil {
		province = *p
	}
	if c != nil {
		country = *c
	}

	subject := pkix.Name{
		Organization:       []string{organization},
		OrganizationalUnit: []string{organizationalUnit},
		CommonName:         commonName,
		Locality:           []string{locality},
		Province:           []string{province},
		Country:            []string{country},
	}
	//	err = policies.CheckPolicy(csrByteString)

	//	if err != nil {
	//		log.Debugf("Policy result: %v", err)
	//		return nil, nil, err
	//	}

	pemCertificate, pemPrivateKey, expiryString, err := GeneratePemCertificate(subject, true)
	return pemCertificate, pemPrivateKey, expiryString, err
}

//openssl x509 -req -days 365 -in tmp.csr -signkey tmp.key -sha256 -out server.crt

func GenerateCSR(name pkix.Name, privateKey interface{}) (csrDerBytes []byte, err error) {
	template := x509.CertificateRequest{
		Subject:            name,
		SignatureAlgorithm: x509.SHA256WithRSA,
	}

	csrDerBytes, err = x509.CreateCertificateRequest(rand.Reader, &template, privateKey)
	return

}

func GenerateRSAKey() (privateKey *rsa.PrivateKey, err error) {
	keyLength := 2048
	privateKey, err = rsa.GenerateKey(rand.Reader, keyLength)
	return
}

// GetSubjectFromCSR get the subject from CSR
func GetSubjectFromCSR(csr string) (subject pkix.Name) {
	csrBytes := []byte(csr)
	p, _ := pem.Decode(csrBytes)

	certrequest, err2 := x509.ParseCertificateRequest(p.Bytes)
	if err2 != nil {
		log.Fatalf("failed to decode CSR: %v", err2)
	}

	commonName := certrequest.Subject.CommonName
	organization := certrequest.Subject.Organization
	organizationalUnit := certrequest.Subject.OrganizationalUnit
	locality := certrequest.Subject.Locality
	province := certrequest.Subject.Province
	country := certrequest.Subject.Country

	subject = pkix.Name{
		Organization:       organization,
		OrganizationalUnit: organizationalUnit,
		CommonName:         commonName,
		Locality:           locality,
		Province:           province,
		Country:            country,
	}
	return
}

// GeneratePemCertificate generates a PEM certificate using a CSR
func GeneratePemCertificate(subject pkix.Name, possiblyUseHSM bool) (pemCertificate []byte, pemPrivateKey []byte, expiryString string, err error) {

	certificate, expiryString := generateX509ertificate(subject, x509.KeyUsageKeyEncipherment|x509.KeyUsageDigitalSignature, false)

	if config.IsHSMEnaabled() {
		if possiblyUseHSM {
			var keyReference string
			log.Debugf("Signing Certificate for %s using HSM - and storing key in HSM", subject.CommonName)
			_, pemCertificate, keyReference, err = GenerateHSMSignedCertificate(certificate, subject.CommonName, subCACert, "EDGECA-SUB-CA")

			pemPrivateKey = []byte(keyReference)
		} else {
			log.Debugf("Signing Certificate for %s using HSM - and storing private key in EdgeCA", subject.CommonName)
			var serverKey *rsa.PrivateKey
			_, pemCertificate, serverKey, err = GenerateHSMSignedCertificateWithPrivateKey(certificate, subCACert, "EDGECA-SUB-CA")

			pemPrivateKey = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(serverKey)})
		}
	} else {
		log.Debugf("Signing certificate")
		var serverKey *rsa.PrivateKey

		_, pemCertificate, serverKey, err = GenerateSignedCertificate(certificate, subCACert, subCAPrivateKey)

		pemPrivateKey = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(serverKey)})

	}
	return
}

//GenerateSelfSignedRootCACertAndKey generates the root certificate
func GenerateSelfSignedRootCACertAndKey() (err error) {

	subject := pkix.Name{
		CommonName: "EdgeCARootCA",
	}
	unsignedCertificate, _ := generateX509ertificate(subject, x509.KeyUsageCertSign|x509.KeyUsageCRLSign, true)

	if config.IsHSMEnaabled() {
		log.Debugf("Generating self signed Root CA Certificate using HSM")

		rootCAPrivateKey = nil
		rootCACert, rootCAPEMCert, _, err = GenerateHSMSignedCertificate(unsignedCertificate, "EDGECA-ROOT-CA", nil, "")

		if err != nil {
			return err
		}
	} else {
		log.Debugf("Generating self signed Root CA Certificate")

		rootCACert, rootCAPEMCert, rootCAPrivateKey, err = GenerateSignedCertificate(unsignedCertificate, nil, nil)
		if err != nil {
			return err
		}
	}
	return nil
}

//GenerateSelfSignedSubCACertAndKey generates the sub CA certificate
func GenerateSelfSignedSubCACertAndKey() (err error) {
	subject := pkix.Name{
		CommonName: "EdgeCASubCA",
	}
	unsignedCertificate, _ := generateX509ertificate(subject, x509.KeyUsageCertSign|x509.KeyUsageCRLSign, true)

	if config.IsHSMEnaabled() {
		log.Debugf("Generating self signed Sub CA Certificate using HSM")

		subCAPrivateKey = nil
		subCACert, subCAPEMCert, _, err = GenerateHSMSignedCertificate(unsignedCertificate, "EDGECA-SUB-CA", rootCACert, "EDGECA-ROOT-CA")

		if err != nil {
			return err
		}
	} else {
		log.Debugf("Generating self signed Sub CA Certificate")

		subCACert, subCAPEMCert, subCAPrivateKey, err = GenerateSignedCertificate(unsignedCertificate, rootCACert, rootCAPrivateKey)
		if err != nil {
			return err
		}
	}
	return nil

}
