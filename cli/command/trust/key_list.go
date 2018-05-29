package trust

import (
	"github.com/docker/cli/cli"
	"github.com/docker/cli/cli/command"
	"github.com/docker/cli/cli/trust"
	"github.com/docker/cli/cli/command/formatter"

	"github.com/spf13/cobra"
	"github.com/theupdateframework/notary/client"
	"github.com/theupdateframework/notary/trustmanager"
	"github.com/theupdateframework/notary/tuf/data"
	"fmt"
	"encoding/json"
)

const (
	jsonFormat = "json"
	prettyFormat = "pretty"
)

var rolesByKeyID = make(map[string][]data.RoleName)

type keyListOptions struct {
	verbose bool		// will display -when supported- additional info: added by, creation date
	format string
}

func newKeyListCommand(dockerCli command.Cli) *cobra.Command {
	var options keyListOptions
	cmd := &cobra.Command{
		Use:   "list [OPTIONS]",
		Short: "List all available keys used by signers",
		Args:  cli.ExactArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			return listKeys(dockerCli, options)
		},
	}
	flags := cmd.Flags()
	flags.BoolVarP(&options.verbose, "verbose", "v", false, "Verbose output for all keys")
	flags.StringVarP(&options.format, "format", "f", prettyFormat, fmt.Sprintf("Format the output, supported formats are: %s, %s", prettyFormat, jsonFormat))

	return cmd
}

func listKeys(dockerCli command.Cli, options keyListOptions) error {
	trustDir := trust.GetTrustDirectory()
	passRetriever := trust.GetPassphraseRetriever(dockerCli.In(), dockerCli.Out())

	keyFileStore, err := trustmanager.NewKeyFileStore(trustDir, passRetriever)
	if err != nil {
		return err
	}

	ks := trustmanager.KeyStore(keyFileStore)

	// TODO(n4ss): does Docker support (or plan to) having the trust config on a Yubikey?
	// if so we should addd it to the keyStores to inspect and display
	keysInfo, err := getKeysInfoFromKeyStore(dockerCli, ks, options.verbose)
	if err != nil {
		return err
	}

	err = printKeysInfo(dockerCli, keysInfo, options.format, options.verbose)
	if err != nil {
		return err
	}

	return nil
}

func registerKeyIDsForRolesWithSigs(rolesWithSigs []client.RoleWithSignatures) {
	for _, roleWithSigs := range rolesWithSigs {
		// FIXME: are we sure that KeyIDs are updated here?
		keyIDs := roleWithSigs.KeyIDs

		for _, keyID := range keyIDs {
			roles, ok := rolesByKeyID[keyID]
			if !ok {
				rolesByKeyID[keyID] = []data.RoleName{roleWithSigs.Name}
			} else {
				rolesByKeyID[keyID] = append(roles, roleWithSigs.Name)
			}
		}
	}
}

func registerKeyIDsForRoles(roles []data.Role) {
	for _, role := range roles {
		keyIDs := role.KeyIDs

		for _, keyID := range keyIDs {
			roles, ok := rolesByKeyID[keyID]
			if !ok {
				rolesByKeyID[keyID] = []data.RoleName{role.Name}
			} else {
				rolesByKeyID[keyID] = append(roles, role.Name)
			}
		}
	}
}

func getRolesByKeyID(keyID string) ([]data.RoleName, error) {
	res, ok := rolesByKeyID[keyID]
	if !ok {
		return nil, fmt.Errorf("key ID: \"%s\" is not associated to a role", keyID)
	}

	return res, nil
}

func getKeysInfoFromKeyStore(dockerCli command.Cli, ks trustmanager.KeyStore, verbose bool) (map[string]formatter.KeyInfo, error) {
	keyIDsToInfo := ks.ListKeys()

	// Per Image (GUN)
	// 		- Root key, Repository key
	// ==> Per Tag
	// 			- Signer (we only have roles)
	// 			- abbreviated Key ID | verbose(full ID)
	// 			- Role
	// 			- TODO(nass): verbose(filesystem location), verbose(date) and other metadata..
	keyIDToImageKeysInfo := make(map[string]formatter.KeyInfo)
	for keyID, info := range keyIDsToInfo {
		var signedTagsInfo []formatter.SignedTagInfo

		currKeyInfo, ok := keyIDToImageKeysInfo[keyID]
		if !ok {
			if len(info.Gun) == 0 {
				// the key has no scope (no associated GUN) so we only format the role for this key
				keyRole := ""
				switch info.Role {
				case data.CanonicalRootRole:
					keyRole = "Root Key"
				case data.CanonicalSnapshotRole:
					keyRole = "Snapshot Key"
				case data.CanonicalTargetsRole:
					keyRole = "Repository Key"
				case data.CanonicalTimestampRole:
					keyRole = "Timestamp Key"
				default:
					keyRole = string(info.Role)
				}

				keyIDToImageKeysInfo[keyID] = formatter.KeyInfo{
					Id: keyID,
					RepoInfo: formatter.RepoTrustInfo{
					},
					Roles: []data.RoleName{data.RoleName(keyRole)},
				}

				continue
			}

			// Get signed tags for the key & key roles info once per GUN
			trustTags, adminRolesWithSigs, delegationRoles, err := lookupTrustInfo(dockerCli, string(info.Gun))
			if err != nil {
				return nil, err
			}

			for _, trustTag := range trustTags {
				signedTagInfo := formatter.SignedTagInfo{
					Name: trustTag.SignedTag,
					Digest: trustTag.Digest,
					Signers: trustTag.Signers,
				}
				signedTagsInfo = append(signedTagsInfo, signedTagInfo)
			}

			registerKeyIDsForRolesWithSigs(adminRolesWithSigs)

			// TODO(nass) we should call getDelegationRoleToKeyMap instead
			registerKeyIDsForRoles(delegationRoles)

			keyRoles, err := getRolesByKeyID(keyID)
			if err != nil {
				return nil, err
			}

			keyIDToImageKeysInfo[keyID] = formatter.KeyInfo{
				Id: keyID,
				RepoInfo: formatter.RepoTrustInfo{
						Image:         info.Gun,
						TagsToSigners: signedTagsInfo,
						},
				Roles: keyRoles,
			}

			continue
		}

		imageInfo := currKeyInfo.RepoInfo
		keyRoles := currKeyInfo.Roles

		switch info.Role {
		case data.CanonicalTargetsRole:
			imageInfo.Repo = keyID
		case data.CanonicalRootRole:
			imageInfo.Root = keyID
		}

		keyIDToImageKeysInfo[keyID] = formatter.KeyInfo{
			Id: keyID,
			RepoInfo: imageInfo,
			Roles: keyRoles,
		}
	}

	fmt.Fprintln(dockerCli.Out(), "getKeysInfoFromKeyStore - end")
	return keyIDToImageKeysInfo, nil

	// Current format
	//
	// User Keys : {
	// 	key-id-1: {
	// 		Role:	"role",
	//		Applied on:
	//			name: "repo/image:tag", digest: "digest",
	// 	}
	// }

	// TODO(nass): use a formatter to display (no-verbose mode) [Preferred format]
	//
	// User Keys : {
    // 	 "<key-id1>" : {
    // 	      Docker User : 	"<username>",
    // 			Allowed to sign:	{
    // 	 			"<repo/image1>[:<tags>]",
    // 				"<repo/image2>[:<tags>]",
    // 	 		},
    // 			Roles : 		"<role1>", "<role2>",
    //	 		Added by:		"username" ("<role>"),
    // 	 },
	//	 "<key-id2>" : {
	//	       Docker User : 	"<username>",
	//	 		Allowed to sign:	{
	//	  			"<repo/image1>[:<tags>]",
	//	 			"<repo/image2>[:<tags>]",
	//	  		},
	//	 		Roles : 		"<role1>", "<role2>",
	//	 		Added by:		"username" ("<role>"),
	// 	 }
    // },
    // Root Keys : {
    //		Image :		"<repo/image>[:<tags>]",
    // },
    // Repository Keys : {
    //		Image : 	"<repo/image>[:<tags>]",
    // }

    // with pretty-printing
    //
    // User Keys:
    // +-----+------+-----------------+-------+----------+
	// | Key | User | Allowed to Sign | Roles | Added by |
	// +-----+------+-----------------+-------+----------+
	// |     |      |                 |       |          |
	// +-----+------+-----------------+-------+----------+
	//
	// Root Keys:
	// +--------+-------------+
	// |  Key   |    Image    |
	// +--------+-------------+
	// |        |             |
	// +--------+-------------+
 }

 func printKeysInfo(dockerCli command.Cli, keysInfo map[string]formatter.KeyInfo, format string, verbose bool) error {
 	switch format {
	case jsonFormat:
		return jsonPrintKeysInfo(dockerCli, keysInfo, verbose)
	case prettyFormat:
		return prettyPrintKeysInfo(dockerCli, keysInfo, verbose)
	default:
		return fmt.Errorf("Unknown specified format, supported formats are: %s, %s", jsonFormat, prettyFormat)
	}
 }

 func jsonPrintKeysInfo(dockerCli command.Cli, keysInfo map[string]formatter.KeyInfo, verbose bool) error {
 	 var infoList []formatter.KeyInfo
	 for _, info := range keysInfo {
	 	newInfo := info
	 	if !verbose {
	 		// this field is `omitempty' so emptying it removes it from the output
	 		newInfo.RepoInfo = formatter.RepoTrustInfo{}
		}
		infoList = append(infoList, newInfo)
	 }

	 keysInfoJSON, err := json.MarshalIndent(infoList, "", "\t")
	 if err != nil {
		 return err
	 }

	 fmt.Fprintln(dockerCli.Out(), string(keysInfoJSON))

 	return nil
 }

 func prettyPrintKeysInfo(dockerCli command.Cli, keysInfo map[string]formatter.KeyInfo, verbose bool) error {
 	// TODO(nass) use formatter package
 	return nil
 }