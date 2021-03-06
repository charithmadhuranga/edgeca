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

package hsm

import (
	"crypto"
	"errors"
	"fmt"
	"os"

	"github.com/ThalesIgnite/crypto11"
	"github.com/edgesec-org/edgeca/internal/config"
	"github.com/google/uuid"
	"github.com/prometheus/common/log"
)

var ctx *crypto11.Context

func setupHSM() (err error) {

	path, token, pin, enabled := config.GetHSMConfiguration()

	if path == "" || token == "" || pin == "" || !enabled {
		return errors.New("HSM is not configured in EdgeCA config file")
	}

	pc := &crypto11.Config{
		Path:       path,
		TokenLabel: token,
		Pin:        pin,
	}

	// this needs to be set for the softhsm library to find the config file
	hsmConfigFile := config.GetSoftHSMConfigFile()
	os.Setenv("SOFTHSM2_CONF", hsmConfigFile)
	log.Infof("SOFTHSM2_CONF file set to %s", hsmConfigFile)
	ctx, err = crypto11.Configure(pc)

	return
}

func ResetConfiguration() {
	ctx = nil
}

func NewHSMSigner(labelString string) (signer crypto.Signer, id []byte, err error) {

	if ctx == nil {
		err = setupHSM()
		if err != nil {
			return nil, nil, err
		}
	}

	label := []byte(labelString)
	idUUID := []byte(uuid.New().String())
	signerDecryptor, err := ctx.GenerateRSAKeyPairWithLabel(idUUID, label, 2048)
	if err != nil {
		return nil, nil, err
	}

	return crypto.Signer(signerDecryptor), idUUID, err

}

func GetHSMSigner(signerName string) (signer crypto.Signer, err error) {

	if ctx == nil {
		err = setupHSM()
		if err != nil {
			return nil, err
		}
	}

	label := []byte(signerName)

	signer, err = ctx.FindKeyPair(nil, label)
	return signer, err

}

func ListHSMAllKeys() (err error) {

	if ctx == nil {
		err = setupHSM()
		if err != nil {
			fmt.Printf("HSM is disabled. Run setup_hsm.sh script to set up\n")
			return nil
		}
	}

	keys, _ := ctx.FindAllKeyPairs()
	fmt.Printf("HSM status: %d keys found:\n\n", len(keys))
	for i, key := range keys {
		a, _ := ctx.GetAttribute(key, crypto11.CkaId)
		fmt.Printf("Key %d: %v\n", i, string(a.Value))
	}
	return nil
}
