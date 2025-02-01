# Zero Downtime Upgrades

## Introduction

This document describes the process of upgrading Valkey to a new version with zero downtime. This is achieved by running multiple instances of a Cluster Shard (IE spooling up a read-only instance of the new version) and then switching the traffic to the new version.

## Prerequisites

Each Cluster Shard must run with-in it's own stateful set. This is to ensure that the data is not lost when the pod is restarted. The stateful set must have a unique name and a unique service name.

The new version of the Cluster Shard must be able to run in read-only mode. This is to ensure that the new version can be spooled up without affecting the existing version. This will be in a separate stateful set.

## Process

1. Spool up a new stateful set with the new version of the Cluster Shard. This stateful set must be in read-only mode. This is to ensure that the new version does not affect the existing version.
2. Once the new stateful set is up and running, switch the traffic to the new stateful set.
3. Once the traffic is switched, the old stateful set can be deleted.
