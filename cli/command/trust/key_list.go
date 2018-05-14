package trust

import (
	"github.com/docker/cli/cli"
	command "github.com/docker/cli/cli/command"
	"github.com/docker/cli/cli/trust"
	"github.com/docker/cli/cli/command/formatter"

	"github.com/spf13/cobra"
	"github.com/theupdateframework/notary/client"
	"github.com/theupdateframework/notary/trustmanager"
	"github.com/theupdateframework/notary/tuf/data"
	"fmt"
)

var rolesByKeyID map[string]data.RoleName

type keyListOptions struct {
	// Display keys with their full digest instead of abbreviated one
	verbose bool
}

type imageKeysInfo struct {
	image data.GUN	// Reference to the image
	root string
	repo string
	tagsToSigners []formatter.SignedTagInfo
}

type keyInfo struct {
	imageInfo imageKeysInfo
	roles []data.RoleName
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

	if err := prettyPrintKeysFromKeyStore(dockerCli, ks, options.verbose) ; err != nil {
		return err
	}

	return nil
}

func registerKeyIDsForRolesWithSigs(rolesWithSigs []client.RoleWithSignatures) {
	for _, roleWithSigs := range rolesWithSigs {
		// FIXME: are we sure that KeyIDs are updated here?
		keyIDs := roleWithSigs.KeyIDs

		for _, keyID := range(keyIDs) {
			rolesByKeyID[keyID] = roleWithSigs.Name
		}
	}
}

func registerKeyIDsForRoles(roles []data.Role) {
	for _, role := range roles {
		keyIDs := role.KeyIDs

		for _, keyID := range(keyIDs) {
			rolesByKeyID[keyID] = role.Name
		}
	}
}

func getRoleByKeyID(keyID string) (data.RoleName, error) {
	res, ok := rolesByKeyID[keyID]
	if !ok {
		return "", fmt.Errorf("key ID: \"%s\" is not associated to a role", keyID)
	}

	return res, nil
}

func prettyPrintKeysFromKeyStore(dockerCli command.Cli, ks trustmanager.KeyStore, verbose bool) error {
	keyIDsToInfo := ks.ListKeys()

	// Per Image (GUN)
	// 		- Root key, Repository key
	// ==> Per Tag
	// 			- Signer (we only have roles)
	// 			- abbreviated Key ID | verbose(full ID)
	// 			- Role
	// 			- TODO(nass): verbose(filesystem location), verbose(date) and other metadata..
	gunToImageKeysInfo := make(map[data.GUN]imageKeysInfo)
	for keyID, info := range keyIDsToInfo {
		var imageInfo imageKeysInfo
		var keyInfo keyInfo
		var signedTagsInfo []formatter.SignedTagInfo

		if res, ok := gunToImageKeysInfo[info.Gun]; ok {
			imageInfo = res
		} else {
			// Get signed tags & signers info once per GUN
			trustTags, adminRolesWithSigs, delegationRoles, err := lookupTrustInfo(dockerCli, string(info.Gun))
			if err != nil {
				return err
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
			registerKeyIDsForRoles(delegationRoles)

			imageInfo = imageKeysInfo{
				image: info.Gun,
				tagsToSigners: signedTagsInfo,
			}
		}

		switch info.Role {
		case data.CanonicalTargetsRole:
			imageInfo.repo = keyID
		case data.CanonicalRootRole:
			imageInfo.root = keyID
		}

		gunToImageKeysInfo[info.Gun] = imageInfo
	}



	return nil

	// Current format
	//
	// User Keys : {
	// 	key-id-1: {
	// 		Role:	"role",
	//		Applied on Images & Tags:
	//			name: "repo/image:tag", digest: "digest", signers "signers",
	//			name:
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