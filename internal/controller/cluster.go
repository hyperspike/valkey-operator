package controller

import (
	"fmt"
	"regexp"
	"slices"

	valkeyClient "github.com/valkey-io/valkey-go"
)

// valkeyCluster represents a Valkey cluster. It contains a list of shards, each with its own nodes.
type valkeyCluster struct {
	shards []*valkeyShard
}

// valkeyShard represents a shard in the Valkey cluster. It contains slot information and a list of nodes.
type valkeyShard struct {
	id      int
	slotMin int
	slotMax int
	nodes   []*valkeyNode
}

// valkeyNode represents a node in the Valkey cluster.
type valkeyNode struct {
	// id is the node id in the Valkey cluster
	id string
	// name is the pod name in Kubernetes
	name string
	// ip is the pod ip in Kubernetes
	ip string
	// port is the port of the Valkey service
	port int
	// flags are the Valkey flags for this pod
	flags []string
	// primary is the id of the primary node when this node is a replica
	primary string
	// connected is true when the pod is reachable from the operator
	connected bool
	// shard is the id of the shard this node belongs to
	shard int
	// client is the Valkey client for this node, if connected.
	client valkeyClient.Client
}

// isPrimary checks if this node is a primary node for the shard in the Valkey cluster.
func (vn *valkeyNode) isPrimary() bool {
	return slices.Contains(vn.flags, "master")
}

// stsPodIndex extracts the pod index number from the pod name. The pod name is expected to be in
// the format <name>-<number>. The pod index is the pod number from a StatefulSet.
func stsPodIndex(podName string) (int, error) {
	pattern := `.*-(\d+)$`
	re := regexp.MustCompile(pattern)

	matches := re.FindStringSubmatch(podName)
	if len(matches) < 2 {
		return 0, fmt.Errorf("no number found in pod name: %s", podName)
	}

	// Convert the captured group to an integer
	var number int
	_, err := fmt.Sscanf(matches[1], "%d", &number)
	if err != nil {
		return 0, fmt.Errorf("failed to parse number: %w", err)
	}

	return number, nil
}
