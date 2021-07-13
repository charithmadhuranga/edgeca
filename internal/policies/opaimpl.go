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

package policies

import (
	"context"
	"errors"
	"io/ioutil"
	"log"
	"strings"

	"github.com/edgesec-org/edgeca/internal/server/tpp"
	"github.com/open-policy-agent/opa/rego"
)

var policy string
var filename string
var defaultO, defaultOU, defaultC, defaultST, defaultL string

func ApplyTPPValues(defaultValues *tpp.DefaultZoneConfiguration, restrictions *tpp.PolicyRegex) {

	createDefaultPolicyFile(restrictions.CommonName, restrictions.Organization, restrictions.OrganizationalUnit,
		restrictions.Province, restrictions.Locality, restrictions.Country)

	defaultO = defaultValues.Organization
	if defaultValues.OrganizationalUnit != nil && len(defaultValues.OrganizationalUnit) > 0 {
		defaultOU = defaultValues.OrganizationalUnit[0]
	}
	defaultC = defaultValues.Country
	defaultST = defaultValues.Province
	defaultL = defaultValues.Locality

}

func GetDefaultValues() (o, ou, c, st, l string) {

	return defaultO, defaultOU, defaultC, defaultST, defaultL
}

func GetCurrentPolicy() string {
	return policy
}

func getPolicyString(values []string, name string) string {

	combined := strings.Join(values, "|")

	if combined != ".*" {
		return "re_match(`" + combined + "`, input.csr.Subject." + name + "[0])\n"
	}
	return ""
}

func createDefaultPolicyFile(commonName, organization, organizationalUnit, province, locality, country []string) {

	// see https://golang.org/src/crypto/x509/x509.go?s=72240:73802#L2281

	tppPolicy := "package edgeca\n" +
		"csr_policy {\n" +
		getPolicyString(organization, "Organization") +
		getPolicyString(organizationalUnit, "OrganizationalUnit") +
		getPolicyString(province, "Province") +
		getPolicyString(locality, "Locality") +
		getPolicyString(country, "Country") +
		"true\n" +
		"}"

	log.Println("Setting Policy to \n---\n", tppPolicy, "\n---\n")
	policy = tppPolicy

}

// LoadPolicy loads the specified policy file
func LoadPolicy(policyFilename string) {
	filename = policyFilename
	content, err := ioutil.ReadFile(policyFilename)
	if err != nil {
		log.Fatal(err)
	}

	// Convert []byte to string and print to screen
	policy = string(content)

}

// CheckPolicy checks the policy
func CheckPolicy(csr string) error {

	if policy == "" {
		log.Println("No policy file was specified")
		return nil
	}

	log.Println("Applying policy from ", filename)

	// create the JSON object with the CSR
	ctx := context.TODO()
	csrquery, _ := rego.New(
		rego.Query("x=data.csr_out.output"), //output.Subject
		rego.Module("", `
		package csr_out
	
		output := crypto.x509.parse_certificate_request(input.csr)
		`),
		rego.Input(map[string]interface{}{"csr": csr})).PrepareForEval(ctx)
	results, err := csrquery.Eval(ctx)
	if err != nil {
		log.Fatalf("unexpected error %s", err)
	}

	// and apply the policy

	query, err := rego.New(
		rego.Query("data.edgeca.csr_policy"), //output.Subject
		rego.Module("", policy),
		rego.Input(map[string]interface{}{"csr": results[0].Bindings["x"]})).PrepareForEval(ctx)

	if err != nil {
		log.Fatalf("unexpected error %s", err)
	}
	results2, err2 := query.Eval(ctx)

	if err2 != nil {
		log.Fatalf("unexpected error %s", err2)
	}

	if len(results2) == 0 {
		return errors.New("Policy rejected CSR")
	}

	return nil
}
