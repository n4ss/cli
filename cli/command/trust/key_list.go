package trust

import (
	"github.com/docker/cli/cli"
	command "github.com/docker/cli/cli/command"
	"github.com/docker/cli/cli/trust"
	"github.com/docker/cli/cli/command/formatter"

	"github.com/spf13/cobra"
	"github.com/theupdateframework/notary/trustmanager"
	"github.com/theupdateframework/notary/tuf/data"
)

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
	if err := prettyPrintKeysFromKeyStore(dockerCli, ks) ; err != nil {
		return err
	}

	return nil
}

func prettyPrintKeysFromKeyStore(dockerCli command.Cli, ks trustmanager.KeyStore) error {
	keyIDsToInfo := ks.ListKeys()

	// Per Image (GUN) -> Per Tag -> Per Signer
	// 		- Root key, Repository key
	// 		- [Signer (we only have roles), abbreviated Key ID | verbose(full ID), Role, verbose(location), verbose(date)]
	gunToImageKeysInfo := make(map[data.GUN]imageKeysInfo)
	for keyID, info := range keyIDsToInfo {
		var keyInfo imageKeysInfo
		var signedTagsInfo []formatter.SignedTagInfo

		if res, ok := gunToImageKeysInfo[info.Gun]; ok {
			keyInfo = res
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
			}

			keyInfo = imageKeysInfo{
				image: info.Gun,
			}
		}

		switch info.Role {
		case data.CanonicalTargetsRole:
			keyInfo.repo = keyID
		case data.CanonicalRootRole:
			keyInfo.root = keyID
		}

		gunToImageKeysInfo[info.Gun] = keyInfo
	}

	return nil


	// TODO(nass): use a formatter to display (no-verbose mode)
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