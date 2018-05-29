package formatter

import (
	"sort"
	"strings"

	"github.com/docker/docker/pkg/stringid"
	"github.com/theupdateframework/notary/tuf/data"
	"fmt"
)

const (
	defaultTrustTagTableFormat   = "table {{.SignedTag}}\t{{.Digest}}\t{{.Signers}}"
	signedTagNameHeader          = "SIGNED TAG"
	trustedDigestHeader          = "DIGEST"
	signersHeader                = "SIGNERS"
	defaultSignerInfoTableFormat = "table {{.Signer}}\t{{.Keys}}"
	signerNameHeader             = "SIGNER"
	keysHeader                   = "KEYS"
	keyInfoTableVerboseFormat    = "table {{.Id}}\t{{.Roles}}\t{{.RepoInfo}}"
	defaultKeyInfoTableFormat    = "table {{.Id}}\t{{.Roles}}"
	keyIDHeader					 = "KEY ID"
	repoInfoHeader               = "REPO INFO"
	rolesHeader					 = "ROLES"
)

// SignedTagInfo represents all formatted information needed to describe a signed tag:
// Name: name of the signed tag
// Digest: hex encoded digest of the contents
// Signers: list of entities who signed the tag
type SignedTagInfo struct {
	Name    string
	Digest  string
	Signers []string
}

// SignerInfo represents all formatted information needed to describe a signer:
// Name: name of the signer role
// Keys: the keys associated with the signer
type SignerInfo struct {
	Name string
	Keys []string
}

// RepoTrustInfo represents all formatted information needed to describe trust data on a repository
// Image: scope of the repository (GUN)
// Root: root key (canonical root role's key)
// Repo: repository key (target key)
// TagToSigners: list of signed tags with associated signing roles
type RepoTrustInfo struct {
	Image data.GUN	`json:"Image"`
	Root string `json:"Root Key ID"`
	Repo string `json:"Repository Key ID"`
	TagsToSigners []SignedTagInfo `json:"Tags and Signers,omitempty"`
}

// KeyInfo represents all formatted information needed to describe a key:
// Id: key identifier
// RepoInfo: associated repository (if any) trust information
// Roles: roles for which this key is loaded
type KeyInfo struct {
	Id string				`json:"Key ID"`
	RepoInfo RepoTrustInfo `json:"Repository Info, omitempty"`
	Roles []data.RoleName `json:"Roles"`
}

// NewTrustTagFormat returns a Format for rendering using a trusted tag Context
func NewTrustTagFormat() Format {
	return defaultTrustTagTableFormat
}

// NewSignerInfoFormat returns a Format for rendering a signer role info Context
func NewSignerInfoFormat() Format {
	return defaultSignerInfoTableFormat
}

// NewKeyInfoFormat returns a Format for rendering a key info Context
func NewKeyInfoFormat() Format {
	return defaultKeyInfoTableFormat
}

// NewKeyInfoFormat returns a Format for rendering a key info Context with verbose information
func NewKeyInfoVerboseFormat() Format {
	return keyInfoTableVerboseFormat
}

// TrustTagWrite writes the context
func TrustTagWrite(ctx Context, signedTagInfoList []SignedTagInfo) error {
	render := func(format func(subContext subContext) error) error {
		for _, signedTag := range signedTagInfoList {
			if err := format(&trustTagContext{s: signedTag}); err != nil {
				return err
			}
		}
		return nil
	}
	trustTagCtx := trustTagContext{}
	trustTagCtx.header = trustTagHeaderContext{
		"SignedTag": signedTagNameHeader,
		"Digest":    trustedDigestHeader,
		"Signers":   signersHeader,
	}
	return ctx.Write(&trustTagCtx, render)
}

type trustTagHeaderContext map[string]string

type trustTagContext struct {
	HeaderContext
	s SignedTagInfo
}

// SignedTag returns the name of the signed tag
func (c *trustTagContext) SignedTag() string {
	return c.s.Name
}

// Digest returns the hex encoded digest associated with this signed tag
func (c *trustTagContext) Digest() string {
	return c.s.Digest
}

// Signers returns the sorted list of entities who signed this tag
func (c *trustTagContext) Signers() string {
	sort.Strings(c.s.Signers)
	return strings.Join(c.s.Signers, ", ")
}

// SignerInfoWrite writes the context
func SignerInfoWrite(ctx Context, signerInfoList []SignerInfo) error {
	render := func(format func(subContext subContext) error) error {
		for _, signerInfo := range signerInfoList {
			if err := format(&signerInfoContext{
				trunc: ctx.Trunc,
				s:     signerInfo,
			}); err != nil {
				return err
			}
		}
		return nil
	}
	signerInfoCtx := signerInfoContext{}
	signerInfoCtx.header = signerInfoHeaderContext{
		"Signer": signerNameHeader,
		"Keys":   keysHeader,
	}
	return ctx.Write(&signerInfoCtx, render)
}

type signerInfoHeaderContext map[string]string

type signerInfoContext struct {
	HeaderContext
	trunc bool
	s     SignerInfo
}

// Keys returns the sorted list of keys associated with the signer
func (c *signerInfoContext) Keys() string {
	sort.Strings(c.s.Keys)
	truncatedKeys := []string{}
	if c.trunc {
		for _, keyID := range c.s.Keys {
			truncatedKeys = append(truncatedKeys, stringid.TruncateID(keyID))
		}
		return strings.Join(truncatedKeys, ", ")
	}
	return strings.Join(c.s.Keys, ", ")
}

// Signer returns the name of the signer
func (c *signerInfoContext) Signer() string {
	return c.s.Name
}

// SignerInfoList helps sort []SignerInfo by signer names
type SignerInfoList []SignerInfo

func (signerInfoComp SignerInfoList) Len() int {
	return len(signerInfoComp)
}

func (signerInfoComp SignerInfoList) Less(i, j int) bool {
	return signerInfoComp[i].Name < signerInfoComp[j].Name
}

func (signerInfoComp SignerInfoList) Swap(i, j int) {
	signerInfoComp[i], signerInfoComp[j] = signerInfoComp[j], signerInfoComp[i]
}

type keyInfoHeaderContext map[string]string

type keyInfoContext struct {
	HeaderContext
	k KeyInfo
}

func (c *keyInfoContext) Id() string {
	return c.k.Id
}

func (c *keyInfoContext) RepoInfo() string {
	tagsAndSigners =
	return fmt.Sprintf("Repo: %s, Root key: %s, Repo key: %s, Tags & Signers: %s", c.k.RepoInfo.Image, c.k.RepoInfo.Root, c.k.RepoInfo.Repo, tagsAndSigners)
}

// KeyInfoWrite writes the context for a key info
func KeyInfoWrite(ctx Context, keyInfo KeyInfo) error {
	render := func(format func(subCtx subContext) error) error {
		if err := format(&keyInfoContext{k: keyInfo}); err != nil {
			return err
		}

		return nil
	}

	keyInfoCtx := keyInfoContext{}
	keyInfoCtx.header = keyInfoHeaderContext{
		"Id": keyIDHeader,
		"RepoInfo":    repoInfoHeader,
		"Roles":   rolesHeader,
	}
	return ctx.Write(&keyInfoCtx, render)
}