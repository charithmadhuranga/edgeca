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
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"log"
)

func PemToRSAPrivateKey(pemKey []byte) (rsaKey *rsa.PrivateKey, err error) {

	key, err := pemToPrivateKey(pemKey)
	if err == nil {
		rsaKey = key.(*rsa.PrivateKey)
	}
	return
}

func PemToCert(pemCert []byte) (cert *x509.Certificate, err error) {

	der, _ := pem.Decode(pemCert)
	if der == nil {
		err = errors.New("Could not decode PEM cert  ")
		return
	}

	derBytes := der.Bytes

	certificate, err := x509.ParseCertificate(derBytes)
	if err != nil {
		log.Println("ParseCertificate failed:", err)
	}
	return certificate, err

}

func pemToPrivateKey(pemKey []byte) (key crypto.PrivateKey, err error) {

	der, _ := pem.Decode(pemKey)
	if der == nil {
		err = errors.New("Could not decode PEM key  ")
		return
	}

	derBytes := der.Bytes

	key, err = x509.ParsePKCS1PrivateKey(derBytes)
	if err != nil {
		key, err = x509.ParsePKCS8PrivateKey(derBytes)
		if err != nil {
			key, err = x509.ParseECPrivateKey(derBytes)
		}
	}
	return
}
