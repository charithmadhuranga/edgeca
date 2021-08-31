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

package cmd

import (
	"github.com/edgesec-org/edgeca/internal/config"
	"github.com/edgesec-org/edgeca/internal/server/hsm"

	"github.com/spf13/cobra"
)

func init() {

	var hsmCmd = &cobra.Command{
		Use:   "hsm",
		Short: "HSM commands",
		Args:  cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {

		}}

	var enableHSMCmd = &cobra.Command{
		Use:   "enable",
		Short: "Enable HSM support",
		Long: `
			`,
		Run: func(cmd *cobra.Command, args []string) {
			config.InitCLIConfiguration(configDir)
			path, tokenLabel, pin, _ := config.GetHSMConfiguration()
			config.SetHSMConfiguration(path, tokenLabel, pin, true)
			config.WriteConfigFile()
		}}
	enableHSMCmd.Flags().StringVarP(&configDir, "confdir", "", configDir, "Configuration Directory")

	var disableHSMCmd = &cobra.Command{
		Use:   "disable",
		Short: "Disable HSM support",
		Long: `
			`,
		Run: func(cmd *cobra.Command, args []string) {
			config.InitCLIConfiguration(configDir)
			path, tokenLabel, pin, _ := config.GetHSMConfiguration()
			config.SetHSMConfiguration(path, tokenLabel, pin, false)
			config.WriteConfigFile()
		}}
	disableHSMCmd.Flags().StringVarP(&configDir, "confdir", "", configDir, "Configuration Directory")

	var statusCmd = &cobra.Command{
		Use:   "status",
		Short: "Show HSM status",
		Long: `
			`,
		Run: func(cmd *cobra.Command, args []string) {
			config.InitCLIConfiguration(configDir)
			hsm.ListHSMAllKeys()
		}}

	configDir = config.GetDefaultConfdir()
	statusCmd.Flags().StringVarP(&configDir, "confdir", "", configDir, "Configuration Directory")

	rootCmd.AddCommand(hsmCmd)
	hsmCmd.AddCommand(statusCmd)
	hsmCmd.AddCommand(enableHSMCmd)
	hsmCmd.AddCommand(disableHSMCmd)

}
