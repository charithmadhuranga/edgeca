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
	"crypto/x509"
	"crypto/x509/pkix"
	"os"
	"testing"

	"github.com/edgesec-org/edgeca/internal/config"
	"github.com/edgesec-org/edgeca/internal/server/hsm"
)

func TestCertificates(t *testing.T) {
	home, _ := os.UserHomeDir()

	config.InitCLIConfiguration(home + "/.edgeca")

	signer, err := hsm.GetHSMSigner("EDGECA-ROOT-CA")
	if err != nil {
		t.Fatalf("GetEdgeRootCASigner %v", err)
	}

	if signer == nil {
		t.Fatalf("GetEdgeRootCASigner signer = nil")
	}

	root := pkix.Name{
		CommonName: "EdgeCARootCA",
	}

	unsignedCertificate, _ := generateX509ertificate(root, x509.KeyUsageCertSign|x509.KeyUsageCRLSign, true)

	parentCertificate, _, err := GenerateHSMSignedCertificate(unsignedCertificate, "EDGECA-ROOT-CA", nil, "")
	if err != nil {
		t.Fatalf("GetEdgeRootCASigner %v", err)
	}

	_, _, err = GenerateHSMSignedCertificate(unsignedCertificate, "EDGECA-SUB-CA", parentCertificate, "EDGECA-ROOT-CA")
	if err != nil {
		t.Fatalf("GetEdgeRootCASigner %v", err)
	}

	config.SetHSMConfiguration("", "", "")
	hsm.ResetConfiguration()

	_, _, err = GenerateHSMSignedCertificate(unsignedCertificate, "EDGECA-ROOT-CA", nil, "")
	if err == nil {
		t.Fatalf("GenerateHSMSignedCertificate should fail when HSM isn't set up")
	}
}
