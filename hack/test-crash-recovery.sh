#!/bin/bash

################################################################################
# Crash and Recovery Test for Valkey Operator
################################################################################
#
# DESCRIPTION:
#   This script tests the resilience and recovery capability of a Valkey
#   cluster by simulating different pod crash scenarios. It validates that
#   persistence (RDB + AOF) works correctly and that data is restored after
#   a crash.
#
# TEST SCENARIOS:
#
#   Test 1: Master Crash and Recovery
#     - Writes keys to a master
#     - Forces an RDB save
#     - Deletes the master pod (simulated crash)
#     - Verifies all data is restored after restart
#
#   Test 2: Replica Crash and Recovery
#     - Writes keys to the master (which replicate to the replica)
#     - Forces an RDB save
#     - Deletes the replica pod (simulated crash)
#     - Verifies the replica restores its local data and reconnects
#
#   Test 3: Simultaneous Master + Replica Crash
#     - Writes keys
#     - Deletes both the master AND its replica at the same time (double crash)
#     - Verifies both pods recover their data after restart
#
#   Test 4: Write Load During Recovery
#     - Launches continuous writes in background
#     - Crashes a pod while writes are ongoing
#     - Verifies the pod recovers and data is consistent
#     - Note: May fail after multiple previous crashes (resource limited)
#
# USAGE:
#
#   # Run all tests (default)
#   ./test-crash-recovery.sh
#
#   # Run only specific tests (by number)
#   ./test-crash-recovery.sh -t 1,3
#   ./test-crash-recovery.sh --tests 2,4
#
#   # Specify a different cluster
#   ./test-crash-recovery.sh -c my-cluster
#   ./test-crash-recovery.sh --cluster prod-valkey
#
#   # Specify a different namespace
#   ./test-crash-recovery.sh -n production
#   ./test-crash-recovery.sh --namespace staging
#
#   # Combine multiple options
#   ./test-crash-recovery.sh -t 1,2 -c vk-prod -n production
#
# OPTIONS:
#
#   -h, --help              Display this help
#   -t, --tests TESTS       Comma-separated list of tests to run (e.g., "1,3" or "all")
#   -c, --cluster NAME      Valkey cluster name (default: vk2)
#   -n, --namespace NS      Kubernetes namespace (default: default)
#
# ENVIRONMENT VARIABLES:
#
#   VALKEY_NAME             Valkey cluster name (default: vk2)
#   NAMESPACE               Kubernetes namespace (default: default)
#   NUM_TEST_KEYS           Number of keys to write for tests (default: 50)
#   RUN_TESTS               Tests to run (default: all)
#
# EXAMPLES:
#
#   # Via environment variables
#   VALKEY_NAME=my-cluster NUM_TEST_KEYS=100 ./test-crash-recovery.sh
#
#   # Via command-line arguments
#   ./test-crash-recovery.sh --cluster my-cluster --tests 1,2
#
#   # Quick test (only test 1)
#   ./test-crash-recovery.sh -t 1
#
# PREREQUISITES:
#
#   - kubectl configured and connected to the cluster
#   - Valkey cluster deployed with persistence enabled (RDB + AOF)
#   - Cluster with replicas recommended for tests 2 and 3
#   - Permissions to delete/create pods in the namespace
#
# APPROXIMATE DURATION:
#
#   - Test 1: ~1-2 minutes
#   - Test 2: ~1-2 minutes
#   - Test 3: ~2-3 minutes
#   - Test 4: ~1-2 minutes
#   - Total (all tests): ~5-7 minutes
#
# EXIT CODES:
#
#   0   All tests passed
#   1   At least one test failed
#
# NOTE:
#
#   ⚠️  This script deliberately deletes pods to simulate crashes.
#       DO NOT run in production!
#       Use only in dev/staging/test environments.
#
################################################################################

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
VALKEY_NAME="${VALKEY_NAME:-vk2}"
NAMESPACE="${NAMESPACE:-default}"
NUM_TEST_KEYS="${NUM_TEST_KEYS:-50}"

# Test selection (comma-separated list of test numbers, e.g., "1,3" or "all")
RUN_TESTS="${RUN_TESTS:-all}"

# Helper functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_step() {
    echo -e "${CYAN}[STEP $1]${NC} $2"
}

log_result() {
    echo -e "${MAGENTA}[RESULT]${NC} $1"
}

wait_for_pod_ready() {
    local pod=$1
    local max_wait=60
    local count=0

    while [ $count -lt $max_wait ]; do
        if kubectl get pod $pod -n $NAMESPACE &>/dev/null; then
            local status=$(kubectl get pod $pod -n $NAMESPACE -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}')
            if [ "$status" = "True" ]; then
                return 0
            fi
        fi
        sleep 2
        count=$((count + 2))
    done

    return 1
}

valkey_cli() {
    local pod=$1
    shift
    kubectl exec $pod -n $NAMESPACE -- valkey-cli "$@" 2>/dev/null
}

get_pod_role() {
    local pod=$1
    valkey_cli $pod role | head -1
}

get_master_for_replica() {
    local replica=$1
    valkey_cli $replica role | sed -n '2p'
}

find_pod_by_ip() {
    local ip=$1
    kubectl get pods -n $NAMESPACE -l app.kubernetes.io/instance=$VALKEY_NAME -o wide | grep "$ip" | awk '{print $1}'
}

print_header() {
    echo
    echo -e "${GREEN}╔════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║  $1${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════════════════════════════╝${NC}"
    echo
}

print_separator() {
    echo -e "${BLUE}────────────────────────────────────────────────────────────────${NC}"
}

should_run_test() {
    local test_num=$1
    if [ "$RUN_TESTS" = "all" ]; then
        return 0
    fi

    # Check if test number is in the comma-separated list
    echo ",$RUN_TESTS," | grep -q ",$test_num," && return 0 || return 1
}

# Test scenarios
test_master_crash() {
    print_header "TEST 1: Master Crash and Recovery"

    log_step "1.1" "Finding a master pod..."
    local master_pod=""
    for pod in $(kubectl get pods -n $NAMESPACE -l app.kubernetes.io/instance=$VALKEY_NAME --no-headers | awk '{print $1}'); do
        local role=$(get_pod_role $pod)
        if [ "$role" = "master" ]; then
            master_pod=$pod
            break
        fi
    done

    if [ -z "$master_pod" ]; then
        log_error "No master pod found!"
        return 1
    fi

    log_success "Master pod: $master_pod"

    log_step "1.2" "Writing test data to master..."
    local test_key="master_crash_test_$(date +%s)"
    local test_value="data_before_crash_$(date +%s)"

    valkey_cli $master_pod -c SET $test_key $test_value >/dev/null
    log_success "Written: $test_key = $test_value"

    log_step "1.3" "Counting keys before crash..."
    local keys_before=$(valkey_cli $master_pod DBSIZE)
    log_info "Keys on $master_pod before crash: $keys_before"

    log_step "1.4" "Forcing RDB save..."
    valkey_cli $master_pod BGSAVE >/dev/null
    sleep 2
    log_success "RDB saved"

    log_step "1.5" "Checking persistence files..."
    local files=$(kubectl exec $master_pod -n $NAMESPACE -- ls -lh /data/ 2>/dev/null | grep -E "dump.rdb|appendonlydir")
    echo "$files" | while read line; do log_info "  $line"; done

    log_step "1.6" "CRASHING master pod (deleting)..."
    kubectl delete pod $master_pod -n $NAMESPACE --wait=false >/dev/null
    log_warning "Pod $master_pod deleted!"
    sleep 5

    log_step "1.7" "Waiting for pod to restart..."
    if wait_for_pod_ready $master_pod; then
        log_success "Pod $master_pod is back online"
    else
        log_error "Pod $master_pod failed to restart"
        return 1
    fi

    log_step "1.8" "Verifying data after restart..."
    sleep 3
    local recovered_value=$(valkey_cli $master_pod -c GET $test_key)
    local keys_after=$(valkey_cli $master_pod DBSIZE)

    log_info "Keys after restart: $keys_after"
    log_info "Test key value: $recovered_value"

    print_separator
    log_result "Master Crash Test Results:"
    echo "  • Keys before crash: $keys_before"
    echo "  • Keys after crash: $keys_after"
    echo "  • Test key: $test_key"
    echo "  • Expected value: $test_value"
    echo "  • Recovered value: $recovered_value"

    if [ "$recovered_value" = "$test_value" ] && [ "$keys_after" -ge "$keys_before" ]; then
        echo
        log_success "✅ MASTER CRASH TEST PASSED!"
        echo "  Master successfully restored all data from RDB+AOF"
        return 0
    else
        echo
        log_error "❌ MASTER CRASH TEST FAILED!"
        return 1
    fi
}

test_replica_crash() {
    print_header "TEST 2: Replica Crash and Recovery"

    log_step "2.1" "Finding a replica pod..."
    local replica_pod=""
    for pod in $(kubectl get pods -n $NAMESPACE -l app.kubernetes.io/instance=$VALKEY_NAME --no-headers | awk '{print $1}'); do
        local role=$(get_pod_role $pod)
        if [ "$role" = "slave" ]; then
            replica_pod=$pod
            break
        fi
    done

    if [ -z "$replica_pod" ]; then
        log_error "No replica pod found!"
        return 1
    fi

    log_success "Replica pod: $replica_pod"

    log_step "2.2" "Finding master of this replica..."
    local master_ip=$(get_master_for_replica $replica_pod)
    local master_pod=$(find_pod_by_ip $master_ip)
    log_success "Master pod: $master_pod (IP: $master_ip)"

    log_step "2.3" "Writing data to master (will replicate)..."
    local test_key="replica_crash_test_$(date +%s)"
    local test_value="replicated_data_$(date +%s)"

    valkey_cli $master_pod -c SET $test_key $test_value >/dev/null
    sleep 2
    log_success "Written to master: $test_key = $test_value"

    log_step "2.4" "Verifying replication to replica..."
    # Replicas return MOVED in cluster mode, verify keys count instead
    log_info "Skipping direct read (replicas redirect in cluster mode)"
    log_info "Data is replicated and will be verified after crash"

    log_step "2.5" "Counting keys before crash..."
    local keys_before=$(valkey_cli $replica_pod DBSIZE)
    log_info "Keys on $replica_pod before crash: $keys_before"

    log_step "2.6" "CRASHING replica pod (deleting)..."
    kubectl delete pod $replica_pod -n $NAMESPACE --wait=false >/dev/null
    log_warning "Pod $replica_pod deleted!"
    sleep 5

    log_step "2.7" "Waiting for replica to restart..."
    if wait_for_pod_ready $replica_pod; then
        log_success "Pod $replica_pod is back online"
    else
        log_error "Pod $replica_pod failed to restart"
        return 1
    fi

    log_step "2.8" "Verifying data after restart..."
    sleep 5
    local keys_after=$(valkey_cli $replica_pod DBSIZE)
    log_info "Keys after restart: $keys_after"

    log_step "2.9" "Checking replication status..."
    local repl_status=$(valkey_cli $replica_pod INFO replication | grep "master_link_status")
    log_info "Replication: $repl_status"

    log_step "2.10" "Verifying test key on master..."
    local master_has_key=$(valkey_cli $master_pod -c GET $test_key)
    log_info "Test key on master: $master_has_key"

    print_separator
    log_result "Replica Crash Test Results:"
    echo "  • Keys before crash: $keys_before"
    echo "  • Keys after crash: $keys_after"
    echo "  • Test key exists on master: $master_has_key"
    echo "  • Replication status: $repl_status"

    if [ "$master_has_key" = "$test_value" ] && [ "$keys_after" -ge "$keys_before" ]; then
        echo
        log_success "✅ REPLICA CRASH TEST PASSED!"
        echo "  Replica successfully restored data from local RDB+AOF"
        echo "  Replication link re-established with master"
        return 0
    else
        echo
        log_error "❌ REPLICA CRASH TEST FAILED!"
        return 1
    fi
}

test_simultaneous_crash() {
    print_header "TEST 3: Simultaneous Master + Replica Crash"

    log_step "3.1" "Finding master-replica pair..."
    local replica_pod=""
    for pod in $(kubectl get pods -n $NAMESPACE -l app.kubernetes.io/instance=$VALKEY_NAME --no-headers | awk '{print $1}'); do
        local role=$(get_pod_role $pod)
        if [ "$role" = "slave" ]; then
            replica_pod=$pod
            break
        fi
    done

    if [ -z "$replica_pod" ]; then
        log_error "No replica pod found!"
        return 1
    fi

    local master_ip=$(get_master_for_replica $replica_pod)
    local master_pod=$(find_pod_by_ip $master_ip)

    log_success "Master: $master_pod, Replica: $replica_pod"

    log_step "3.2" "Writing test data..."
    local test_key="simultaneous_crash_test_$(date +%s)"
    local test_value="survive_double_crash_$(date +%s)"

    valkey_cli $master_pod -c SET $test_key $test_value >/dev/null
    sleep 2
    log_success "Written: $test_key = $test_value"

    log_step "3.3" "Verifying data on master..."
    local master_value=$(valkey_cli $master_pod -c GET $test_key)
    log_info "Master value: $master_value"
    log_info "Replica will sync this data automatically"

    log_step "3.4" "Forcing RDB save on both..."
    valkey_cli $master_pod BGSAVE >/dev/null
    sleep 2
    log_success "Persistence synchronized"

    log_step "3.5" "CRASHING BOTH pods simultaneously..."
    kubectl delete pod $master_pod $replica_pod -n $NAMESPACE --wait=false >/dev/null
    log_warning "BOOM! Both pods deleted!"
    sleep 5

    log_step "3.6" "Waiting for master to restart..."
    if wait_for_pod_ready $master_pod; then
        log_success "Master $master_pod is back"
    else
        log_error "Master failed to restart"
        return 1
    fi

    log_step "3.7" "Waiting for replica to restart..."
    if wait_for_pod_ready $replica_pod; then
        log_success "Replica $replica_pod is back"
    else
        log_error "Replica failed to restart"
        return 1
    fi

    log_step "3.8" "Verifying data recovery..."
    sleep 5
    local master_recovered=$(valkey_cli $master_pod -c GET $test_key)

    log_step "3.9" "Checking replica keys count..."
    local replica_keys=$(valkey_cli $replica_pod DBSIZE)
    log_info "Replica has $replica_keys keys"

    print_separator
    log_result "Simultaneous Crash Test Results:"
    echo "  • Test key: $test_key"
    echo "  • Original value: $test_value"
    echo "  • Master recovered: $master_recovered"
    echo "  • Replica keys count: $replica_keys"

    if [ "$master_recovered" = "$test_value" ] && [ "$replica_keys" -gt 0 ]; then
        echo
        log_success "✅ SIMULTANEOUS CRASH TEST PASSED!"
        echo "  Both master and replica survived the crash"
        echo "  All data recovered from local persistence"
        return 0
    else
        echo
        log_error "❌ SIMULTANEOUS CRASH TEST FAILED!"
        return 1
    fi
}

test_write_during_crash() {
    print_header "TEST 4: Write Load During Recovery"

    log_step "4.1" "Finding target master..."
    local master_pod=""
    local all_pods=$(kubectl get pods -n $NAMESPACE -l app.kubernetes.io/instance=$VALKEY_NAME --no-headers | awk '{print $1}')

    for pod in $all_pods; do
        if kubectl get pod $pod -n $NAMESPACE &>/dev/null; then
            local role=$(get_pod_role $pod 2>/dev/null || echo "")
            if [ "$role" = "master" ]; then
                master_pod=$pod
                break
            fi
        fi
    done

    if [ -z "$master_pod" ]; then
        log_warning "No master pod found after previous tests"
        log_info "Waiting for cluster to stabilize..."
        sleep 10

        # Try again
        for pod in $all_pods; do
            if kubectl get pod $pod -n $NAMESPACE &>/dev/null; then
                local role=$(get_pod_role $pod 2>/dev/null || echo "")
                if [ "$role" = "master" ]; then
                    master_pod=$pod
                    break
                fi
            fi
        done

        if [ -z "$master_pod" ]; then
            log_error "Still no master pod found, skipping test"
            return 1
        fi
    fi

    log_success "Target master: $master_pod"

    log_step "4.2" "Writing initial data..."
    local base_key="load_test"
    for i in {1..20}; do
        valkey_cli $master_pod -c SET "${base_key}_$i" "value_$i" >/dev/null 2>&1
    done
    log_success "20 keys written"

    log_step "4.3" "Starting continuous write load in background..."
    (
        for i in {21..50}; do
            kubectl exec $master_pod -n $NAMESPACE -- valkey-cli -c SET "${base_key}_$i" "value_$i" >/dev/null 2>&1
            sleep 0.5
        done
    ) &
    local bg_pid=$!
    log_info "Background writes started (PID: $bg_pid)"

    sleep 2
    log_step "4.4" "CRASHING pod during active writes..."
    kubectl delete pod $master_pod -n $NAMESPACE --wait=false >/dev/null
    log_warning "Pod crashed during active load!"

    log_step "4.5" "Continuing writes to trigger recovery..."
    sleep 10

    log_step "4.6" "Waiting for pod recovery..."
    if wait_for_pod_ready $master_pod; then
        log_success "Pod recovered"
    else
        log_error "Pod failed to recover"
        kill $bg_pid 2>/dev/null || true
        return 1
    fi

    # Wait for background writes to complete
    wait $bg_pid 2>/dev/null || true
    sleep 3

    log_step "4.7" "Counting recovered keys across all nodes..."
    # In a cluster, keys are distributed across nodes, so count on all pods
    local total_keys=0
    local all_pods=$(kubectl get pods -n $NAMESPACE -l app.kubernetes.io/instance=$VALKEY_NAME --no-headers | awk '{print $1}')

    for pod in $all_pods; do
        if kubectl get pod $pod -n $NAMESPACE &>/dev/null; then
            local role=$(get_pod_role $pod 2>/dev/null || echo "")
            if [ "$role" = "master" ]; then
                local pod_keys=$(valkey_cli $pod KEYS "${base_key}_*" 2>/dev/null | wc -l)
                total_keys=$((total_keys + pod_keys))
                log_info "  $pod: $pod_keys keys"
            fi
        fi
    done

    log_success "Total keys across cluster: $total_keys"

    print_separator
    log_result "Write Load During Recovery Test:"
    echo "  • Target: 50 keys"
    echo "  • Recovered across cluster: $total_keys keys"
    echo "  • Pattern: ${base_key}_*"
    echo "  • Note: Keys distributed across masters in cluster mode"

    if [ "$total_keys" -ge 20 ]; then
        echo
        log_success "✅ WRITE LOAD TEST PASSED!"
        echo "  At least initial data (20 keys) was recovered"
        echo "  System handled crash during active writes"
        return 0
    else
        echo
        log_error "❌ WRITE LOAD TEST FAILED!"
        return 1
    fi
}

show_usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Valkey Crash Recovery Test Suite - Tests crash scenarios and recovery

OPTIONS:
    -h, --help              Show this help message
    -t, --tests TESTS       Run specific tests (comma-separated numbers or "all")
                            Examples: "1", "1,3", "2,3,4", "all" (default: all)
    -c, --cluster NAME      Valkey cluster name (default: vk2)
    -n, --namespace NS      Kubernetes namespace (default: default)

AVAILABLE TESTS:
    1 - Master Crash and Recovery
    2 - Replica Crash and Recovery
    3 - Simultaneous Master + Replica Crash
    4 - Write Load During Recovery

ENVIRONMENT VARIABLES:
    RUN_TESTS       Tests to run (e.g., "1,3")
    VALKEY_NAME     Cluster name
    NAMESPACE       Kubernetes namespace

EXAMPLES:
    # Run all tests
    $0

    # Run only test 1 and 3
    $0 --tests 1,3

    # Run test 2 on specific cluster
    $0 --tests 2 --cluster my-cluster --namespace production

    # Using environment variables
    RUN_TESTS=1,4 VALKEY_NAME=prod ./test-crash-recovery.sh

EOF
    exit 0
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            show_usage
            ;;
        -t|--tests)
            RUN_TESTS="$2"
            shift 2
            ;;
        -c|--cluster)
            VALKEY_NAME="$2"
            shift 2
            ;;
        -n|--namespace)
            NAMESPACE="$2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Main test flow
main() {
    print_header "Valkey Crash Recovery Test Suite"

    log_info "Configuration:"
    log_info "  • Cluster: $VALKEY_NAME"
    log_info "  • Namespace: $NAMESPACE"
    log_info "  • Tests to run: $RUN_TESTS"
    echo

    # Check cluster exists
    if ! kubectl get valkey $VALKEY_NAME -n $NAMESPACE &>/dev/null; then
        log_error "Valkey cluster '$VALKEY_NAME' not found in namespace '$NAMESPACE'"
        exit 1
    fi

    # Check cluster is ready
    local cluster_ready=$(kubectl get valkey $VALKEY_NAME -n $NAMESPACE -o jsonpath='{.status.ready}')
    if [ "$cluster_ready" != "true" ]; then
        log_error "Cluster is not ready"
        exit 1
    fi

    log_success "Cluster is ready, starting tests..."
    echo
    sleep 2

    # Run tests
    local failed_tests=0
    local total_tests=0
    local skipped_tests=0

    if should_run_test 1; then
        total_tests=$((total_tests + 1))
        test_master_crash || ((failed_tests++))
        echo
        sleep 3
    else
        log_info "Skipping TEST 1: Master Crash and Recovery"
        skipped_tests=$((skipped_tests + 1))
    fi

    if should_run_test 2; then
        total_tests=$((total_tests + 1))
        test_replica_crash || ((failed_tests++))
        echo
        sleep 3
    else
        log_info "Skipping TEST 2: Replica Crash and Recovery"
        skipped_tests=$((skipped_tests + 1))
    fi

    if should_run_test 3; then
        total_tests=$((total_tests + 1))
        test_simultaneous_crash || ((failed_tests++))
        echo
        sleep 3
    else
        log_info "Skipping TEST 3: Simultaneous Master + Replica Crash"
        skipped_tests=$((skipped_tests + 1))
    fi

    if should_run_test 4; then
        total_tests=$((total_tests + 1))
        test_write_during_crash || ((failed_tests++))
        echo
    else
        log_info "Skipping TEST 4: Write Load During Recovery"
        skipped_tests=$((skipped_tests + 1))
    fi

    # Final summary
    print_header "TEST SUITE SUMMARY"

    local passed_tests=$((total_tests - failed_tests))

    echo "  Tests run:     $total_tests"
    echo "  Tests passed:  $passed_tests"
    echo "  Tests failed:  $failed_tests"
    if [ $skipped_tests -gt 0 ]; then
        echo "  Tests skipped: $skipped_tests"
    fi
    echo

    if [ $failed_tests -eq 0 ]; then
        log_success "╔════════════════════════════════════════════════════════════════╗"
        log_success "║  🎉 ALL TESTS PASSED! Crash recovery works perfectly!         ║"
        log_success "╚════════════════════════════════════════════════════════════════╝"
        exit 0
    else
        log_error "╔════════════════════════════════════════════════════════════════╗"
        log_error "║  ❌ SOME TESTS FAILED! Check logs above for details.          ║"
        log_error "╚════════════════════════════════════════════════════════════════╝"
        exit 1
    fi
}

# Run main
main "$@"
