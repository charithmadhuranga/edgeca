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

package certs

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"math/big"
	"time"
)

var serialNumber big.Int
var rootCert *x509.Certificate
var rsaRootKey *rsa.PrivateKey
var derRsaRootCert []byte

var subCACert *x509.Certificate
var rsasubCAKey *rsa.PrivateKey
var dersubCACert []byte

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

	log.Printf("Signing certificate (CN=%v)", commonName)

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

//GenerateSelfSignedSubCACertAndKey generates the sub CA certificate
func GenerateSelfSignedSubCACertAndKey(parentCert *x509.Certificate, parentKey *rsa.PrivateKey) (certificate *x509.Certificate, pemSubCert []byte, rsasubCAKey *rsa.PrivateKey, err error) {
	log.Printf("Generating self signed Sub CA Certificate")

	rsasubCAKey, err = GenerateRSAKey()
	if err != nil {
		return nil, nil, nil, err
	}

	subject := pkix.Name{
		CommonName: "EdgeCASubCA",
	}

	unsignedCertificate := generateX509ertificate(subject, x509.KeyUsageCertSign|x509.KeyUsageCRLSign, true)

	derRsaCert, err := signCertificateAndDEREncode(unsignedCertificate, parentCert, parentKey, rsasubCAKey)
	if err != nil {
		return nil, nil, nil, err
	}

	certificate, err = x509.ParseCertificate(derRsaCert)
	if err != nil {
		return nil, nil, nil, err
	}

	pemSubCert = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derRsaCert})
	return
}

// GeneratePemCertificate generates a PEM certificate using a CSR
func GeneratePemCertificate(subject pkix.Name, parentCert *x509.Certificate, parentKey *rsa.PrivateKey) (pemCertificate []byte, pemPrivateKey []byte, err error) {

	certificate := generateX509ertificate(subject,
		x509.KeyUsageKeyEncipherment|x509.KeyUsageDigitalSignature, false)

	var serverKey *rsa.PrivateKey
	serverKey, err = GenerateRSAKey()

	derServerCert, err := signCertificateAndDEREncode(certificate, parentCert, parentKey, serverKey)
	if err != nil {
		return nil, nil, err
	}

	pemCertificate = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derServerCert})
	pemPrivateKey = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(serverKey)})

	return
}

//GenerateSelfSignedRootCACertAndKey generates the root certificate
func GenerateSelfSignedRootCACertAndKey() (certificate *x509.Certificate, pemCACert []byte, rsaRootKey *rsa.PrivateKey, err error) {
	log.Printf("Generating self signed Root CA Certificate")

	rsaRootKey, err = GenerateRSAKey()
	if err != nil {
		return nil, nil, nil, err
	}

	subject := pkix.Name{
		CommonName: "EdgeCARootCA",
	}

	unsignedCertificate := generateX509ertificate(subject, x509.KeyUsageCertSign|x509.KeyUsageCRLSign, true)

	derRsaRootCert, err = signCertificateAndDEREncode(unsignedCertificate, unsignedCertificate, rsaRootKey, rsaRootKey)
	if err != nil {
		log.Println("signCertificateAndDEREncode failed:", err)
		return nil, nil, nil, err
	}

	certificate, err = x509.ParseCertificate(derRsaRootCert)
	if err != nil {
		log.Println("ParseCertificate failed:", err)
	}

	pemCACert = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derRsaRootCert})

	return
}

func generateX509ertificate(subject pkix.Name, keyUsage x509.KeyUsage, isCA bool) *x509.Certificate {

	notBefore := time.Now()
	notAfter := notBefore.Add(time.Hour)

	var cert x509.Certificate

	cert = x509.Certificate{
		SerialNumber:          &serialNumber,
		Subject:               subject,
		DNSNames:              []string{subject.CommonName},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		BasicConstraintsValid: true,
		KeyUsage:              keyUsage,
		IsCA:                  isCA,
	}

	//	if !isCA {
	//		cert.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	//	}

	serialNumber.Add(&serialNumber, big.NewInt(1))

	return &cert

}

func signCertificateAndDEREncode(certificate, parent *x509.Certificate, parentPrivateKey *rsa.PrivateKey, privateKey *rsa.PrivateKey) (der []byte, err error) {

	der, err = x509.CreateCertificate(rand.Reader, certificate, parent, &privateKey.PublicKey, parentPrivateKey)

	return
}

func certificateChain() {
	//	certPool := x509.NewCertPool()
	//	certPool.AddCert(rootCert)
}
