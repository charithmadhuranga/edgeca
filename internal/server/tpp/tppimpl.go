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

package tpp

import (
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"log"
	"time"

	"github.com/Venafi/vcert/v4"
	"github.com/Venafi/vcert/v4/pkg/certificate"
	"github.com/Venafi/vcert/v4/pkg/endpoint"

	certs "github.com/edgesec-org/edgeca/internal/issuer"
)

func connect(url, zone, token string) (endpoint.Connector, error) {
	config := &vcert.Config{
		ConnectorType: endpoint.ConnectorTypeTPP,
		BaseUrl:       url,
		Zone:          zone,
		Credentials: &endpoint.Authentication{
			AccessToken: token}}

	c, err := vcert.NewClient(config)
	if err != nil {

		errorString := "Error:could not connect to endpoint:" + err.Error()
		log.Println(errorString)
	}

	return c, err
}

// DefaultZoneConfiguration provides the default values for certificate requests as defined by the TPP policy
type DefaultZoneConfiguration struct {
	Organization       string
	OrganizationalUnit []string
	Country            string
	Province           string
	Locality           string
	//HashAlgorithm         x509.SignatureAlgorithm
	//CustomAttributeValues map[string]string
	//KeyConfiguration      *AllowedKeyConfiguration
}

// PolicyRegex provides the restrictions for certificates as defined by the TPP policy
type PolicyRegex struct {
	CommonName         []string
	Organization       []string
	OrganizationalUnit []string
	Province           []string
	Locality           []string
	Country            []string
	//	AllowedKeyConfigurations []AllowedKeyConfiguration
	//	DnsSanRegExs []string
	//	IpSanRegExs    []string
	//	EmailSanRegExs []string
	//	UriSanRegExs   []string
	//	UpnSanRegExs   []string
	//	AllowWildcards bool
	//	AllowKeyReuse  bool
}

func TPPGetPolicy(url, zone, token string) (defaultConfiguration *DefaultZoneConfiguration, restrictions *PolicyRegex, err error) {
	log.Println("TPP: get policy  ")
	var defaults DefaultZoneConfiguration
	var rest PolicyRegex

	c, err := connect(url, zone, token)
	if err != nil {
		log.Fatalln("TPP Error:", err.Error())
		return nil, nil, err
	}

	zoneConfig, err := c.ReadZoneConfiguration()
	if err != nil {
		log.Fatalln("TPP Error:", err.Error())
		return nil, nil, err
	}

	log.Println("TPP: get default configuration  ")

	defaults.Organization = zoneConfig.Organization
	defaults.OrganizationalUnit = zoneConfig.OrganizationalUnit
	defaults.Country = zoneConfig.Country
	defaults.Province = zoneConfig.Province
	defaults.Locality = zoneConfig.Locality

	log.Println("TPP: ReadPolicyConfiguration  ")
	policy, err := c.ReadPolicyConfiguration()
	if err != nil {
		log.Fatalln("TPP Error:", err.Error())
		return nil, nil, err
	}
	rest.CommonName = policy.SubjectCNRegexes
	rest.Organization = policy.SubjectORegexes
	rest.OrganizationalUnit = policy.SubjectOURegexes
	rest.Province = policy.SubjectSTRegexes
	rest.Locality = policy.SubjectLRegexes
	rest.Country = policy.SubjectCRegexes
	return &defaults, &rest, err
}

// TPPGenerateCertificateChainAndKey generates a certificate using TPP
func TPPGenerateCertificateChainAndKey(url, zone, token string, subject pkix.Name) (pemChain string, pemCertificate string, pemPrivateKey string, err error) {
	log.Println("TPP: sending request for ", subject.CommonName)

	c, err := connect(url, zone, token)

	//
	// 1.1. Compose request object
	//
	//Not all Venafi Cloud providers support IPAddress and EmailAddresses extensions.
	var enrollReq = &certificate.Request{
		Subject: pkix.Name{
			CommonName: subject.CommonName,
		},
		CsrOrigin:   certificate.LocalGeneratedCSR,
		KeyType:     certificate.KeyTypeRSA,
		KeyLength:   2048,
		ChainOption: certificate.ChainOptionRootLast,
	}

	zoneConfig, err := c.ReadZoneConfiguration()
	if err != nil {
		log.Println("TPP Error:", err.Error())
		return "", "", "", err
	}

	log.Printf("Successfully read zone configuration for %s\n", zone)

	err = c.GenerateRequest(zoneConfig, enrollReq)
	if err != nil {
		log.Println("Error:", err.Error())
		return "", "", "", err
	}

	log.Printf("Successfully created request for %s\n", subject.CommonName)

	//
	// 1.3. Submit certificate request, get request ID as a response
	//
	requestID, err := c.RequestCertificate(enrollReq)
	if err != nil {
		log.Println("Error:", err.Error())
		return "", "", "", err
	}

	//	caCert, err = generateSelfSigned(&caReq, x509.KeyUsageKeyEncipherment|x509.KeyUsageDigitalSignature|x509.KeyUsageCertSign, []x509.ExtKeyUsage{x509.ExtKeyUsageAny}, caPriv)

	//
	// 1.4. Retrieve certificate using request ID obtained on previous step, get PEM collection as a response
	//
	pickupReq := &certificate.Request{
		PickupID: requestID,
		Timeout:  180 * time.Second,
	}

	pcc, err := c.RetrieveCertificate(pickupReq)
	if err != nil {
		log.Println("Retrieving " + pickupReq.PickupID + " : " + err.Error())
		return "", "", "", err
	}

	//
	// 1.5. (optional) Add certificate's private key to PEM collection
	//
	err = pcc.AddPrivateKey(enrollReq.PrivateKey, []byte(enrollReq.KeyPassword))
	if err != nil {
		log.Println("Retrieving " + pickupReq.PickupID + " : " + err.Error())
		return "", "", "", err
	}

	pemCertificate = pcc.Certificate
	pemPrivateKey = pcc.PrivateKey
	pemChain = pcc.Chain[0]

	if len(pcc.Chain) != 1 {
		errStr := "Error: certificate chain size <> 1 (" + string(len(pcc.Chain)) + ")"
		err = errors.New(errStr)
	}

	if pemCertificate == "" {
		err = errors.New("Error: certificate = nil")
	} else if pemPrivateKey == "" {
		err = errors.New("Error: Private Key = nil")
	}
	return

}

// GenerateTPPRootCACertAndKey generates CA issuing cert and key using TPP
func GenerateTPPRootCACertAndKey(url, zone, token string) (rootCert *x509.Certificate, pemRootCACert []byte, subCert *x509.Certificate, pemSubCACert []byte, rsaRootKey *rsa.PrivateKey, err error) {
	log.Printf("Request Root CA Certificate using TPP")
	subject := pkix.Name{
		CommonName: "EdgeCASubCA",
	}
	var pemKey string

	chain, cert, pemKey, err := TPPGenerateCertificateChainAndKey(url, zone, token, subject)

	if err != nil {
		log.Println(string("Could not generate issuing cert:"), err.Error())
	} else {
		rsaRootKey, err = certs.PemToRSAPrivateKey([]byte(pemKey))
		pemRootCACert = []byte(chain)
		pemSubCACert = []byte(cert)
		rootCert, err = certs.PemToCert(pemRootCACert)
		subCert, err = certs.PemToCert(pemSubCACert)

		if !subCert.IsCA {
			err = errors.New("subCert is not a CA certificate")
			return nil, nil, nil, nil, nil, err
		} else if !rootCert.IsCA {
			err = errors.New("rootCert is not a CA certificate")
			return nil, nil, nil, nil, nil, err
		}
	}

	return
}

/*

func vCertGetCred(url, zone, username, password, clientID string) (result string, err error) {

	var connectionTrustBundle *x509.CertPool
	var tppConnector *tpp.Connector
	var resp tpp.OauthGetRefreshTokenResponse

	tppConnector, err = tpp.NewConnector(url, zone, false, connectionTrustBundle)
	if err != nil {
		return "", err
	}

	resp, err = tppConnector.GetRefreshToken(&endpoint.Authentication{
		User:     username,
		Password: password,
		Scope:    "certificate:manage,revoke;",
		ClientId: clientID})
	if err != nil {
		return "", err
	}

	return resp.Access_token, nil
}

func vCertGetCert(url, token) {

	//   -	use vcert-webassembly code
	//   -	look at use of policies


}

*/
