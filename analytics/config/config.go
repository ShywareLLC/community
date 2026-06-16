package config

// Config holds the indexer configuration.
type Config struct {
	CometBFT   CometBFTConfig   `yaml:"cometbft"`
	PostgreSQL PostgreSQLConfig `yaml:"postgresql"`
}

// CometBFTConfig holds CometBFT connection settings.
type CometBFTConfig struct {
	RPC string `yaml:"rpc"` // e.g. http://localhost:26657
}

// PostgreSQLConfig holds PostgreSQL connection settings.
type PostgreSQLConfig struct {
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	Database string `yaml:"database"`
	User     string `yaml:"user"`
	Password string `yaml:"password"`
	URL      string `yaml:"url"` // full connection string (takes precedence)
}
