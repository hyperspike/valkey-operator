package cfg

var (
	// Default Settings
	DefaultSidecarImage string
	DefaultValkeyImage  string
	DefaultNodes        int = 3
)

type Config struct {
	// The default clusterwide prometheus exporter image to use
	SidecarImage string `json:"sidecarImage"`
	// The default clusterwide valkey image to use
	ValkeyImage string `json:"valkeyImage"`
	// The default number of nodes to use
	Nodes int `json:"nodes"`
}

func Defaults() *Config {
	return &Config{
		SidecarImage: DefaultSidecarImage,
		ValkeyImage:  DefaultValkeyImage,
		Nodes:        DefaultNodes,
	}
}
