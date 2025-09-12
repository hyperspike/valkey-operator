package cfg

var (
	// Default Settings
	DefaultSidecarImage string
	DefaultValkeyImage  string
	DefaultNodes        int32 = 3
)

type Config struct {
	// The default clusterwide prometheus exporter image to use
	SidecarImage string `json:"exporterImage"`
	// The default clusterwide valkey image to use
	ValkeyImage string `json:"valkeyImage"`
	// The default number of nodes to use
	Nodes int32 `json:"nodes"`
}

func Defaults() *Config {
	return &Config{
		SidecarImage: DefaultSidecarImage,
		ValkeyImage:  DefaultValkeyImage,
		Nodes:        DefaultNodes,
	}
}
