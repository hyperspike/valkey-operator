# Roadmap

## v0.1.0

### Important Features

1. Init all nodes with distinct config epocs, (1, 2, 3, etc. rather than 0, 0, 0...). This is similar to what `valkey-cli --cluster create` does, but it's probably better to implement it in the operator rather than calling out to `cluster-cli`.
  2. CLUSTER MEET and K8S redisness-probe after meet.
  3. Check that the node is in the cluster (e.g. using CLUSTER NODES).
  4. Migrate slots to it or start replicating from another node.
  5. Rediness gate (on the pod) until a replica has finished loading/replicating.
  6. Check that the node is part of the cluster and has slots
* Upgrade, without impact on the redundancy:
  1. Add one new upgraded pod and make it a replica of an existing primary.
  2. Upgrade all other replica nodes of this primary, one by one or a few at a time. (This can be done be removing an old and adding a new upgraded one in its place.)
  3. Trigger a manual failover to one of the replicas.
  4. Remove the old primary.
* Anti-affinity:
  * Replicas and primary of the same shard need be spread out across different K8s workers.
  * Primaries should be evenly distributed across K8s workers.
* K8s worker upgrade, without service impact. Similar to upgrading Valkey, this is done without any reduced redundancy.
  1. Add a new worker.
  2. Add replicas to it.
  3. For the primaries on the old worker, trigger manual failover to replicas on the new worker.
  4. Remove the nodes on the old worker from the valkey cluster using CLUSTER FORGET.
  4. Remove the old worker.
* Orchestrate scaling. Scale in/out without service impact.
  1. Add new primary and replicas (if scaling out).
  2. Move cluster slots (valkey keys) to it from the other shards, to spread the data evenly among the primaries.
  3. Remove nodes (if scaling in).
* Future: Auto-scaling. Check which shards have more traffic, CPU and/or memory usage than the others and balance the keys among the shards to adjust these metrics. (Such metrics were added in Valkey 8 for this purpose. I believe they will use it in AWS.)
  * There are ideas about whether it would be possible to use K8s Horizontal Pod Autoscaler. (Requires
  ReplicaSet? One ReplicaSet per worker? Some smart way to use labels on the pods?)

When you start a pod, I don't know if you can fully control on which worker the pod is started. I suppose it depends how the pods are managed (deployment, stateful set, or just manually by the operator). You may be able to add labels on pods and set up rule according to that. If you can't fully control on which worker a pod is stared, you can at least manipulate the valkey cluster by moving replicas between primaries and by triggering manual failover.
The main problem with stateful set, according to the people I've talked to, is the netsplit scenario. Assume some pod is not reachable by the operator, but it's still alive on a different worker and writing to its disk storage. In this case, the stateful set will never delete the pod, because it can't guarantee that it's not writing to its disk. Maybe you can force-delete it? Is that a good way? If it's actually writing to a disk, it might not be a good idea to start a new pod writing to the same storage. Also, it's not desirable to have potential old zombie pods around.
For this reason, they're using only diskless replication, no storage and no stateful sets. With this setup, a pod can be deleted at any time, even if the operator doesn't know if it's alive or not.
It might be possible to do all this with stateful set, or with multiple stateful sets, but you don't get this for free just by using stateful set. Apparently, you get the most control by just managing the pods directly from the operator.

## Existing Operators

  * [IBM](https://ibm.github.io/operator-for-redis-cluster/)
  * [Amadeus](https://github.com/AmadeusITGroup/Redis-Operator)
  * [Ops Tree](https://ot-container-kit.github.io/redis-operator/#/quickstart/quickstart)

