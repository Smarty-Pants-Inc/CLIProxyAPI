// Package config provides the public SDK configuration API.
//
// It re-exports the server configuration types and helpers so external projects can
// embed CLIProxyAPI without importing internal packages.
package config

import internalconfig "github.com/router-for-me/CLIProxyAPI/v7/internal/config"

var (
	ErrConfigConflict        = internalconfig.ErrConfigConflict
	ErrConfigVersionRequired = internalconfig.ErrConfigVersionRequired
)

type APIKeyPolicy = internalconfig.APIKeyPolicy

type SDKConfig = internalconfig.SDKConfig

type Config = internalconfig.Config

type StreamingConfig = internalconfig.StreamingConfig
type ClaudeCodeConfig = internalconfig.ClaudeCodeConfig
type TLSConfig = internalconfig.TLSConfig
type DiscoveryConfig = internalconfig.DiscoveryConfig
type DiscoveryInterfacesConfig = internalconfig.DiscoveryInterfacesConfig
type RemoteManagement = internalconfig.RemoteManagement
type OAuthModelAlias = internalconfig.OAuthModelAlias
type PayloadConfig = internalconfig.PayloadConfig
type PayloadRule = internalconfig.PayloadRule
type PayloadFilterRule = internalconfig.PayloadFilterRule
type PayloadModelRule = internalconfig.PayloadModelRule

type GeminiKey = internalconfig.GeminiKey
type CodexKey = internalconfig.CodexKey
type XAIKey = internalconfig.XAIKey
type XAIModel = internalconfig.XAIModel
type MetaKey = internalconfig.MetaKey
type MetaModel = internalconfig.MetaModel
type ClaudeKey = internalconfig.ClaudeKey
type VertexCompatKey = internalconfig.VertexCompatKey
type VertexCompatModel = internalconfig.VertexCompatModel
type OpenAICompatibility = internalconfig.OpenAICompatibility
type OpenAICompatibilityAPIKey = internalconfig.OpenAICompatibilityAPIKey
type OpenAICompatibilityModel = internalconfig.OpenAICompatibilityModel

type TLS = internalconfig.TLSConfig

const (
	DefaultPanelGitHubRepository = internalconfig.DefaultPanelGitHubRepository
)

func LoadConfig(configFile string) (*Config, error) { return internalconfig.LoadConfig(configFile) }

func LoadConfigOptional(configFile string, optional bool) (*Config, error) {
	return internalconfig.LoadConfigOptional(configFile, optional)
}

func ParseConfigBytes(data []byte) (*Config, error) { return internalconfig.ParseConfigBytes(data) }

// PrepareConfigPublication validates bytes and hashes only the management-key scalar.
func PrepareConfigPublication(data []byte) ([]byte, error) {
	return internalconfig.PrepareConfigPublication(data)
}

func SaveConfigPreserveComments(configFile string, cfg *Config) error {
	return internalconfig.SaveConfigPreserveComments(configFile, cfg)
}

// SaveConfigPreserveCommentsCAS publishes cfg only when the file has expectedVersion.
func SaveConfigPreserveCommentsCAS(configFile string, cfg *Config, expectedVersion string) (string, error) {
	return internalconfig.SaveConfigPreserveCommentsCAS(configFile, cfg, expectedVersion)
}

func ConfigFileVersion(configFile string) (string, error) {
	return internalconfig.ConfigFileVersion(configFile)
}

func AtomicWriteConfig(configFile string, data []byte) error {
	return internalconfig.AtomicWriteConfig(configFile, data)
}

func AtomicWriteConfigCAS(configFile string, data []byte, expectedVersion string) (string, error) {
	return internalconfig.AtomicWriteConfigCAS(configFile, data, expectedVersion)
}

func SaveConfigPreserveCommentsUpdateNestedScalar(configFile string, path []string, value string) error {
	return internalconfig.SaveConfigPreserveCommentsUpdateNestedScalar(configFile, path, value)
}

func NormalizeCommentIndentation(data []byte) []byte {
	return internalconfig.NormalizeCommentIndentation(data)
}
