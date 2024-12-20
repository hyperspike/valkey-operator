package cfg

type Config struct {
	// The default clusterwide prometheus exporter image to use
	ExporterImage string `json:"exporterImage"`
	// The default clusterwide valkey image to use
	ValkeyImage string `json:"valkeyImage"`
	// The default number of nodes to use
	Nodes int `json:"nodes"`
}

func Defaults() *Config {
	return &Config{
		ExporterImage: "docker.io/bitnami/redis-exporter:1.63.0-debian-12-r0",
		ValkeyImage:   "docker.io/bitnami/valkey-cluster:8.0.1-debian-12-r0",
		Nodes:         3,
	}
}
