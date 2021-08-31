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
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"

	"github.com/edgesec-org/edgeca/internal/server/hsm"
	log "github.com/sirupsen/logrus"
)

func signCertificateAndDEREncode(certificate, parent *x509.Certificate, parentPrivateKey *rsa.PrivateKey, privateKey *rsa.PrivateKey) (der []byte, err error) {
	der, err = x509.CreateCertificate(rand.Reader, certificate, parent, &privateKey.PublicKey, parentPrivateKey)
	return
}

func generateX509ertificate(subject pkix.Name, keyUsage x509.KeyUsage, isCA bool) (*x509.Certificate, string) {

	notBefore := time.Now()
	notAfter := notBefore.AddDate(1, 0, 0)

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
	notAfterStr := fmt.Sprintf(cert.NotAfter.Format(time.RFC3339))

	return &cert, notAfterStr

}

func GenerateHSMSignedCertificate(unsignedCertificate *x509.Certificate, signerName string, parent *x509.Certificate, parentSignerName string) (*x509.Certificate, []byte, error) {

	signer, err := hsm.GetHSMSigner(signerName)
	if err != nil {
		log.Debugln("GenerateHSMSignedCertificate failed:", err)
		return nil, nil, err
	}

	var parentSigner crypto.Signer

	if parent == nil {
		parent = unsignedCertificate
		parentSigner = signer
	} else {
		parentSigner, err = hsm.GetHSMSigner(parentSignerName)
		if err != nil {
			log.Debugln("GenerateHSMSignedCertificate failed:", err)
			return nil, nil, err
		}
	}
	derRsaRootCert, err := x509.CreateCertificate(rand.Reader, unsignedCertificate, parent, signer.Public(), parentSigner)

	if err != nil {
		log.Debugln("GenerateHSMSignedCertificate failed:", err)
		return nil, nil, err
	}

	certificate, err := x509.ParseCertificate(derRsaRootCert)
	if err != nil {
		log.Debugln("GenerateHSMSignedCertificate failed:", err)
		return nil, nil, err
	}

	pemCACert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derRsaRootCert})
	return certificate, pemCACert, nil

}

func GenerateHSMSignedCertificateWithPrivateKey(unsignedCertificate *x509.Certificate, parent *x509.Certificate, parentSignerName string) (*x509.Certificate, []byte, *rsa.PrivateKey, error) {

	privateKey, _ := GenerateRSAKey()

	parentSigner, err := hsm.GetHSMSigner(parentSignerName)
	if err != nil {
		log.Debugln("GenerateHSMSignedCertificateWithPrivateKey GetHSMSigner failed:", err)
		return nil, nil, nil, err
	}

	derRsaRootCert, err := x509.CreateCertificate(rand.Reader, unsignedCertificate, parent, &privateKey.PublicKey, parentSigner)

	if err != nil {
		log.Debugln("GenerateHSMSignedCertificateWithPrivateKey CreateCertificate failed:", err)
		return nil, nil, nil, err
	}

	certificate, err := x509.ParseCertificate(derRsaRootCert)
	if err != nil {
		log.Debugln("GenerateHSMSignedCertificateWithPrivateKey ParseCertificate failed:", err)
		return nil, nil, nil, err
	}

	pemCACert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derRsaRootCert})
	return certificate, pemCACert, privateKey, nil

}

func GenerateSignedCertificate(unsignedCertificate *x509.Certificate, parent *x509.Certificate, parentPrivateKey *rsa.PrivateKey) (*x509.Certificate, []byte, *rsa.PrivateKey, error) {

	privateKey, err := GenerateRSAKey()

	if err != nil {
		return nil, nil, nil, err
	}

	if parent == nil {
		parent = unsignedCertificate
		parentPrivateKey = privateKey
	}

	derRsaRootCert, err := signCertificateAndDEREncode(unsignedCertificate, parent, parentPrivateKey, privateKey)
	if err != nil {
		return nil, nil, nil, err
	}

	certificate, err := x509.ParseCertificate(derRsaRootCert)

	if err != nil {
		return nil, nil, nil, err
	}

	pemCACert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derRsaRootCert})

	return certificate, pemCACert, privateKey, nil
}
