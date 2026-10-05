#!/usr/bin/env python3
"""
Automated Test Orchestrator for Stage II (In-Kernel & Fast-Path Performance Evaluation)
Replicating the experimental methodology of:
Hara & Sasabe, "Practicality of in-kernel/user-space packet processing empowered by
lightweight neural network and decision tree", Computer Networks 240 (2024) 110188.

Features:
- Controls 'trafficGen' (Client) using kernel pktgen (exact 10000:10000 UDP flow).
- Controls 'experiment' (Server) to configure NIC queues, CPU isolation, and eBPF/XDP programs.
- Captures rxpps.log, txpps.log, and mpstat.json for CPU utilization breakdown.
- Automatically aggregates results into a summary CSV for direct plotting in thesis.
- NUMA-aware IRQ pinning and per-core SoftIRQ measurement on both Client and Server.
"""

import os
import sys
import time
import json
import argparse
import subprocess
from datetime import datetime
from pathlib import Path

# ==============================================================================
# CONFIGURATION - ADJUST DEFAULTS HERE OR OVERRIDE VIA CLI ARGUMENTS
# ==============================================================================
DEFAULT_CLIENT_HOST = "trafficGen"         # SSH alias from ~/.ssh/config
DEFAULT_SERVER_HOST = "experiment"         # SSH alias from ~/.ssh/config

DEFAULT_CLIENT_IFNAME = "enp2s0np2"       # Intel X710 interface name on Client
DEFAULT_SERVER_IFNAME = "enp2s0np3"       # Intel X710 interface name on Server

DEFAULT_SERVER_IP = "10.0.1.1"            # Destination IP address
DEFAULT_SERVER_MAC = "b4:83:51:01:49:77"  # Destination MAC address (Server X710)

DEFAULT_SERVER_REPO_PATH = "/root/ebpf-classifier"  # Path to repository on Server
DEFAULT_LOCAL_RESULTS_DIR = "./results_stage2"      # Local directory to store logs

def ensure_writable_results_dir(requested_path):
    """Ensures results directory is on a writable filesystem, falling back to home or /tmp if on a read-only mount."""
    candidate = Path(os.path.expanduser(requested_path)).resolve()
    for test_dir in [candidate, Path.home() / "results_stage2", Path("/tmp/results_stage2")]:
        try:
            test_dir.mkdir(parents=True, exist_ok=True)
            test_file = test_dir / ".write_test"
            test_file.write_text("ok")
            test_file.unlink()
            if test_dir != candidate:
                print(f"[!] Notice: '{candidate}' is on a read-only filesystem.")
                print(f"    Automatically redirecting results to writable path: {test_dir}\n")
            return test_dir
        except (OSError, PermissionError):
            continue
    raise RuntimeError("Could not find any writable directory for results (tried candidate, home, and /tmp).")

DEFAULT_TEST_DURATION = 100               # Duration per test run in seconds (paper used 100)
DEFAULT_COOLDOWN = 5                      # Cooldown in seconds between test runs

# Map test sending intervals (microseconds) to theoretical offered PPS and pktgen pacing.
# Is is the inter-packet sending interval in microseconds.
# Is = 0 us represents unconstrained wire-speed flood (10GbE 64B line rate: 14.88 Mpps).
# For Is >= 1, Theoretical Offered PPS = 1,000,000 / Is.
INTERVAL_CONFIGS = {
    0:  {"expected_pps": 14880952, "delay_ns": 0,     "ratep": 0},  # Is = 0 us: unconstrained 10GbE wire flood (14.88 Mpps)
    1:  {"expected_pps": 1000000,  "delay_ns": 1000,  "ratep": 0},  # Is = 1 us -> 1,000,000 pps (1 Mpps)
    2:  {"expected_pps": 500000,   "delay_ns": 2000,  "ratep": 0},  # Is = 2 us -> 500,000 pps
    3:  {"expected_pps": 333333,   "delay_ns": 3000,  "ratep": 0},  # Is = 3 us -> 333,333 pps
    4:  {"expected_pps": 250000,   "delay_ns": 4000,  "ratep": 0},  # Is = 4 us -> 250,000 pps
    5:  {"expected_pps": 200000,   "delay_ns": 5000,  "ratep": 0},  # Is = 5 us -> 200,000 pps
    6:  {"expected_pps": 166667,   "delay_ns": 6000,  "ratep": 0},  # Is = 6 us -> 166,667 pps
    7:  {"expected_pps": 142857,   "delay_ns": 7000,  "ratep": 0},  # Is = 7 us -> 142,857 pps
    8:  {"expected_pps": 125000,   "delay_ns": 8000,  "ratep": 0},  # Is = 8 us -> 125,000 pps
    9:  {"expected_pps": 111111,   "delay_ns": 9000,  "ratep": 0},  # Is = 9 us -> 111,111 pps
    10: {"expected_pps": 100000,   "delay_ns": 10000, "ratep": 0},  # Is = 10 us -> 100,000 pps
}

# ==============================================================================
# SSH HELPER FUNCTIONS
# ==============================================================================
def ssh_exec(host, command, check=True, capture=False):
    """Executes a command over SSH."""
    cmd = ["ssh", host, command]
    if capture:
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if check and res.returncode != 0:
            print(f"[ERROR] SSH command failed on {host}:\n{command}\nStderr:\n{res.stderr}", file=sys.stderr)
            res.check_returncode()
        return res.stdout.strip()
    else:
        res = subprocess.run(cmd)
        if check and res.returncode != 0:
            res.check_returncode()
        return None

def ssh_popen(host, command):
    """Starts a non-blocking background command over SSH."""
    cmd = ["ssh", host, command]
    return subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

# ==============================================================================
# NUMA TOPOLOGY DISCOVERY & CLIENT (PKTGEN) CONTROL
# ==============================================================================
_NUMA_CPU_CACHE = {}

def _parse_cpulist(cpulist_str):
    """Parses a Linux sysfs cpulist string (e.g. '0-27,56-83' or '0,2,4') into a list of ints."""
    cpus = []
    if not cpulist_str:
        return cpus
    for part in cpulist_str.strip().split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            try:
                start, end = map(int, part.split("-"))
                cpus.extend(range(start, end + 1))
            except ValueError:
                pass
        elif part.isdigit():
            cpus.append(int(part))
    return cpus

def get_remote_numa_cpus(host, ifname, count=1):
    """Discovers the NUMA node for a given network interface on host,
    and returns a list of CPU IDs belonging to that NUMA node/socket.
    Prefers physical cores over sibling hyperthreads when possible."""
    key = (host, ifname)
    if key not in _NUMA_CPU_CACHE:
        script = f"""
        node=$(cat /sys/class/net/{ifname}/device/numa_node 2>/dev/null || echo 0)
        if [ -z "$node" ] || [ "$node" -lt 0 ] 2>/dev/null; then node=0; fi
        if [ -f "/sys/devices/system/node/node${{node}}/cpulist" ]; then
            cat /sys/devices/system/node/node${{node}}/cpulist 2>/dev/null
        else
            cat /sys/devices/system/cpu/online 2>/dev/null || echo "0-$(($(nproc --all 2>/dev/null || echo 1) - 1))"
        fi
        """
        res = ssh_exec(host, script, capture=True)
        cpus = _parse_cpulist(res)
        if not cpus:
            cpus = list(range(max(count, 1)))
        _NUMA_CPU_CACHE[key] = cpus

    all_cpus = list(_NUMA_CPU_CACHE[key])
    if count <= len(all_cpus):
        return all_cpus[:count]

    # If requested count exceeds single-socket/node core count, retrieve all online CPUs to avoid truncation
    sys_key = (host, "__all_online_cpus__")
    if sys_key not in _NUMA_CPU_CACHE:
        res = ssh_exec(host, "cat /sys/devices/system/cpu/online 2>/dev/null || echo 0", capture=True)
        sys_cpus = _parse_cpulist(res)
        if not sys_cpus:
            sys_cpus = list(range(count))
        _NUMA_CPU_CACHE[sys_key] = sys_cpus

    all_system = _NUMA_CPU_CACHE[sys_key]
    combined = all_cpus + [c for c in all_system if c not in all_cpus]
    if count <= len(combined):
        return combined[:count]
    return combined

def stop_pktgen(client_host):
    """Stops and clears all active pktgen workers across all CPUs on Client."""
    script = (
        "if [ -f /proc/net/pktgen/pgctrl ]; then "
        "  echo 'stop' > /proc/net/pktgen/pgctrl 2>/dev/null || true; "
        "  sleep 0.5; "
        "  echo 'reset' > /proc/net/pktgen/pgctrl 2>/dev/null || true; "
        "  for th in /proc/net/pktgen/kpktgend_*; do "
        "    [ -f \"$th\" ] && echo 'rem_device_all' > \"$th\" 2>/dev/null || true; "
        "  done; "
        "fi; "
        "killall -9 hping3 2>/dev/null || true"
    )
    ssh_exec(client_host, script, check=False)

def start_pktgen(client_host, client_ifname, server_ip, server_mac, interval_us, num_threads=1, rate_limit=0):
    """Starts pktgen with UDP traffic bound to the NUMA node of the client interface.
    Supports single-flow baseline (num_threads=1) or multi-queue RSS entropy (num_threads > 1)."""
    cfg = INTERVAL_CONFIGS.get(interval_us, {"ratep": 0, "delay_ns": 0, "expected_pps": 14880952})
    delay_ns = cfg.get("delay_ns", 0)
    expected_pps = cfg.get("expected_pps", 14880952)

    # Discover CPUs on the socket/NUMA node owning client_ifname
    target_cpus = get_remote_numa_cpus(client_host, client_ifname, count=num_threads)
    actual_threads = len(target_cpus)
    print(f"    [*] Client NUMA binding: {actual_threads} worker(s) pinned to Socket CPUs: {target_cpus}")

    # Log pacing strategy
    if interval_us == 0:
        if rate_limit > 0:
            print(f"    [*] Pktgen mode: Rate-limited flood ({rate_limit:,} pps cap across {actual_threads} worker(s))")
        else:
            print(f"    [*] Pktgen mode: Unconstrained wire flood (burst 32, delay 0)")
    else:
        if rate_limit > 0 and expected_pps > rate_limit:
            print(f"    [*] Pktgen mode: Rate-limited interval {interval_us}us (capped to {rate_limit:,} pps from {expected_pps:,} pps)")
        else:
            thread_delay_ns = delay_ns * actual_threads
            print(f"    [*] Pktgen mode: Interval-paced ({interval_us}us -> target {expected_pps:,} pps, thread delay: {thread_delay_ns}ns)")

    thread_setup_cmds = []
    for q_idx, cpu in enumerate(target_cpus):
        dev_alias = f"{client_ifname}@{q_idx}" if actual_threads > 1 else client_ifname

        # Pacing and burst settings:
        # In flood mode (interval_us == 0):
        # - When rate_limit is set, cap to rate_limit with burst 0.
        # - Otherwise, use burst 32 (skb->xmit_more batching) with clone_skb 0 for maximum line rate.
        # In interval mode (interval_us > 0):
        # - When rate_limit is set and expected_pps > rate_limit (e.g. Is = 1us with 800k limit),
        #   cap to rate_limit per thread.
        # - Otherwise, pace by interval delay (delay_ns * actual_threads).
        if interval_us == 0:
            if rate_limit > 0:
                ratep_per_thread = max(1, rate_limit // actual_threads)
                burst_cmd = f"echo 'burst 0' > /proc/net/pktgen/{dev_alias}"
                clone_cmd = f"echo 'clone_skb 0' > /proc/net/pktgen/{dev_alias}"
                pacing_cmd = f"echo 'ratep {ratep_per_thread}' > /proc/net/pktgen/{dev_alias}"
            else:
                burst_cmd = f"echo 'burst 32' > /proc/net/pktgen/{dev_alias}"
                clone_cmd = f"echo 'clone_skb 0' > /proc/net/pktgen/{dev_alias}"
                pacing_cmd = f"echo 'delay 0' > /proc/net/pktgen/{dev_alias}"
        else:
            burst_cmd = f"echo 'burst 0' > /proc/net/pktgen/{dev_alias}"
            clone_cmd = f"echo 'clone_skb 0' > /proc/net/pktgen/{dev_alias}"
            if rate_limit > 0 and expected_pps > rate_limit:
                ratep_per_thread = max(1, rate_limit // actual_threads)
                pacing_cmd = f"echo 'ratep {ratep_per_thread}' > /proc/net/pktgen/{dev_alias}"
            elif delay_ns > 0:
                thread_delay_ns = delay_ns * actual_threads
                pacing_cmd = f"echo 'delay {thread_delay_ns}' > /proc/net/pktgen/{dev_alias}"
            else:
                pacing_cmd = f"echo 'delay 0' > /proc/net/pktgen/{dev_alias}"

        # Multi-queue TX mapping and UDP flow entropy
        # 16 flows per queue -> max 256 flows across 16 queues (comfortably fits in 1024-entry BPF sessions table)
        if actual_threads > 1:
            q_map_cmd = f"""
            echo 'queue_map_min {q_idx}' > /proc/net/pktgen/{dev_alias}
            echo 'queue_map_max {q_idx}' > /proc/net/pktgen/{dev_alias}
            """
            udp_src_min = 10000 + q_idx * 16
            udp_src_max = 10000 + q_idx * 16 + 15
        else:
            q_map_cmd = ""
            udp_src_min = 10000
            udp_src_max = 10000

        thread_setup_cmds.append(f"""
        echo 'rem_device_all' > /proc/net/pktgen/kpktgend_{cpu} 2>/dev/null || true
        echo 'add_device {dev_alias}' > /proc/net/pktgen/kpktgend_{cpu}
        echo 'count 0' > /proc/net/pktgen/{dev_alias}
        echo 'pkt_size 64' > /proc/net/pktgen/{dev_alias}
        {burst_cmd}
        {clone_cmd}
        {pacing_cmd}
        {q_map_cmd}
        echo 'dst {server_ip}' > /proc/net/pktgen/{dev_alias}
        echo 'dst_mac {server_mac}' > /proc/net/pktgen/{dev_alias}
        echo 'udp_src_min {udp_src_min}' > /proc/net/pktgen/{dev_alias}
        echo 'udp_src_max {udp_src_max}' > /proc/net/pktgen/{dev_alias}
        echo 'udp_dst_min 10000' > /proc/net/pktgen/{dev_alias}
        echo 'udp_dst_max 10000' > /proc/net/pktgen/{dev_alias}
        """)

    all_threads_script = "\n".join(thread_setup_cmds)

    script = f"""
    modprobe pktgen 2>/dev/null || true
    echo 'stop' > /proc/net/pktgen/pgctrl 2>/dev/null || true
    sleep 0.2
    echo 'reset' > /proc/net/pktgen/pgctrl 2>/dev/null || true

    # Configure client NIC combined queues & rings to match worker count
    ethtool -L {client_ifname} combined {actual_threads} 2>/dev/null || true
    ethtool -G {client_ifname} tx 4096 2>/dev/null || true
    ethtool -C {client_ifname} adaptive-tx off tx-usecs 0 2>/dev/null || true

    {all_threads_script}

    nohup bash -c "echo 'start' > /proc/net/pktgen/pgctrl" </dev/null >/dev/null 2>&1 &
    """
    ssh_exec(client_host, script)

# ==============================================================================
# SERVER (EBPF/XDP) CONTROL
# ==============================================================================
def cleanup_server(server_host, server_ifname):
    """Sends SIGINT so python finally blocks write rxpps.log, then detaches XDP."""
    script = f"""
    killall -SIGINT python3 python 2>/dev/null || true
    sleep 1.5
    ip link set dev {server_ifname} xdp off 2>/dev/null || true
    ip link set dev {server_ifname} xdpgeneric off 2>/dev/null || true
    tc qdisc del dev {server_ifname} clsact 2>/dev/null || true
    killall -9 python3 python 2>/dev/null || true
    """
    ssh_exec(server_host, script, check=False)

def configure_server_cores_and_queues(server_host, server_ifname, num_threads, server_cpus=None, offline_cpus=False):
    """Sets CPU isolation and NIC queue counts matching the thread configuration,
    strictly pinning IRQs to the CPUs on the NUMA node where the server NIC is located."""
    if server_cpus is None:
        server_cpus = get_remote_numa_cpus(server_host, server_ifname, count=num_threads)

    cpus_comma = ",".join(str(c) for c in server_cpus)
    cpus_space = " ".join(str(c) for c in server_cpus)

    chcpu_cmd = ""
    if offline_cpus:
        chcpu_cmd = f"""
        # Ensure target test CPUs are online
        chcpu -e {cpus_comma} >/dev/null 2>&1 || true
        # Attempt to disable non-target CPUs
        max_cpu=$(($(nproc --all 2>/dev/null || echo 4) - 1))
        for ((c=0; c<=max_cpu; c++)); do
            case ",{cpus_comma}," in
                *",$c,"*) ;;
                *) chcpu -d $c >/dev/null 2>&1 || true ;;
            esac
        done
        sleep 0.5
        """
    else:
        chcpu_cmd = f"""
        chcpu -e {cpus_comma} >/dev/null 2>&1 || true
        """

    script = f"""
    # 1. Dynamic CPU online/offline
    {chcpu_cmd}

    # 2. Configure combined queues, balance hardware RSS table equally, and enable 4-tuple UDP hash
    ethtool -L {server_ifname} combined {num_threads} 2>/dev/null || true
    ethtool -X {server_ifname} equal {num_threads} 2>/dev/null || true
    ethtool -K {server_ifname} ntuple off 2>/dev/null || true
    ethtool -N {server_ifname} rx-flow-hash udp4 sdfn 2>/dev/null || ethtool -U {server_ifname} rx-flow-hash udp4 sdfn 2>/dev/null || true
    ethtool -G {server_ifname} rx 4096 tx 4096 2>/dev/null || true
    ethtool -C {server_ifname} adaptive-rx off rx-usecs 0 2>/dev/null || true
    sleep 0.5

    # 3. Pin IRQs 1-to-1 to active CPUs on the NIC's NUMA node
    systemctl stop irqbalance 2>/dev/null || true
    irqs=$(grep -E "{server_ifname}-TxRx|{server_ifname}-rx|{server_ifname}.*TxRx" /proc/interrupts | grep -v -i "misc" | awk '{{print $1}}' | tr -d ':')
    if [ -z "$irqs" ]; then
        irqs=$(grep "{server_ifname}" /proc/interrupts | grep -v -i "misc" | awk '{{print $1}}' | tr -d ':')
    fi
    if [ -z "$irqs" ]; then
        irqs=$(grep "{server_ifname}" /proc/interrupts | awk '{{print $1}}' | tr -d ':')
    fi

    target_cpus=({cpus_space})
    num_target_cpus=${{#target_cpus[@]}}
    q=0
    for irq in $irqs; do
        idx=$((q % num_target_cpus))
        target_cpu=${{target_cpus[$idx]}}
        echo $target_cpu > /proc/irq/$irq/smp_affinity_list 2>/dev/null || true
        q=$((q + 1))
    done
    """
    ssh_exec(server_host, script, check=False)

def restore_server_cores(server_host):
    """Re-enables all CPU cores on the server and restarts irqbalance upon test suite completion."""
    script = """
    max_cpu=$(($(nproc --all 2>/dev/null || echo 4) - 1))
    chcpu -e 0-$max_cpu 2>/dev/null || true
    systemctl start irqbalance 2>/dev/null || true
    """
    ssh_exec(server_host, script, check=False)

# ==============================================================================
# CODE SYNC HELPER
# ==============================================================================
def sync_code_to_server(args):
    """Syncs local updated classifier scripts to the server repository."""
    local_repo = Path(__file__).resolve().parent.parent
    files_to_sync = [
        "filter/filter_xdp.py",
        "dt-filter/dt_filter_xdp.py",
        "nn-filter/nn_filter_xdp.py"
    ]
    print(f"[*] Syncing updated classifier scripts to {args.server}:{args.server_repo_path}...")
    for rel_path in files_to_sync:
        src = local_repo / rel_path
        if src.exists():
            remote_path = f"{args.server}:{args.server_repo_path}/{rel_path}"
            res = subprocess.run(["scp", str(src), remote_path],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            if res.returncode == 0:
                print(f"    [OK] Synced {rel_path}")
            else:
                print(f"    [!] Warning: Failed to sync {rel_path}: {res.stderr.strip()}")

# ==============================================================================
# EXPERIMENT RUNNER
# ==============================================================================
def run_single_trial(args, mode, ml_model, num_threads, interval_us):
    """Runs one individual trial for the specified (mode, ml, threads, interval)."""
    trial_name = f"{mode}_ml-{ml_model}_{num_threads}th_u{interval_us}"
    print(f"\n================================================================================")
    print(f"[*] Starting Trial: {trial_name}")
    print(f"    Mode: {mode} | ML Model: {ml_model} | Threads: {num_threads} | Interval: {interval_us}us")
    print(f"================================================================================")

    # Define remote directories on server and clean any stale logs from previous trials
    remote_logdir = f"{args.server_repo_path}/results/stage2/{mode}/{ml_model}/{num_threads}threads/u{interval_us}"
    ssh_exec(args.server, f"rm -rf {remote_logdir} && mkdir -p {remote_logdir}")

    # Determine server program script path and flag
    flag = ""
    if mode == "xdp_drv":
        app_name = f"{ml_model}_filter_xdp.py" if ml_model != "filter" else "filter_xdp.py"
        flag = "-D"
    elif mode == "xdp_skb":
        app_name = f"{ml_model}_filter_xdp.py" if ml_model != "filter" else "filter_xdp.py"
        flag = "-S"
    elif mode == "tc":
        app_name = f"{ml_model}_filter_tc.py" if ml_model != "filter" else "filter_tc.py"
    elif mode == "userspace":
        app_name = f"{ml_model}_filter_rawsocket_us.py" if ml_model != "filter" else "filter_rawsocket_us.py"
    else:
        raise ValueError(f"Unknown mode: {mode}")

    subdir = "filter" if ml_model == "filter" else f"{ml_model}-filter"
    app_path = f"{args.server_repo_path}/{subdir}/{app_name}"

    # 1. Clean up both machines
    stop_pktgen(args.client)
    cleanup_server(args.server, args.server_ifname)
    time.sleep(1)

    # 2. Discover server NUMA cores and configure server hardware & queues
    server_cpus = get_remote_numa_cpus(args.server, args.server_ifname, count=num_threads)
    print(f"    [*] Server NUMA binding: {len(server_cpus)} core(s) on Socket CPUs: {server_cpus}")
    configure_server_cores_and_queues(
        args.server,
        args.server_ifname,
        num_threads,
        server_cpus=server_cpus,
        offline_cpus=getattr(args, "offline_cpus", False)
    )

    # 3. Start server classifier program with handshake on [CLASSIFIER_READY]
    # For 1 thread, pin directly to the primary NUMA core; for multi-thread, allow socket distribution
    taskset_prefix = f"taskset -c {server_cpus[0]} " if num_threads == 1 else ""
    classifier_log = f"{remote_logdir}/classifier.log"
    pid_file = f"{remote_logdir}/classifier.pid"

    start_classifier_script = f"""
    cd {args.server_repo_path}/{subdir}
    {taskset_prefix}python3 -u {app_path} {args.server_ifname} {remote_logdir} {flag} > {classifier_log} 2>&1 &
    PID=$!
    echo $PID > {pid_file}
    """
    print(f"[*] Starting server classifier: {app_name} {flag} (logging to {classifier_log})...")
    ssh_exec(args.server, start_classifier_script)

    print("    [*] Waiting for classifier to compile eBPF and attach XDP hook...")
    wait_ready_cmd = f"""
    PID=$(cat {pid_file} 2>/dev/null || echo "")
    for i in $(seq 1 30); do
        if [ -n "$PID" ] && ! kill -0 $PID 2>/dev/null; then
            exit 42
        fi
        if grep -q "\\[CLASSIFIER_READY\\]" {classifier_log} 2>/dev/null; then
            exit 0
        fi
        sleep 0.5
    done
    exit 43
    """
    ready_res = subprocess.run(["ssh", args.server, wait_ready_cmd],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if ready_res.returncode == 42:
        print(f"\n[!] ERROR: Server classifier '{app_name}' crashed during startup/compilation!")
        err_log = ssh_exec(args.server, f"cat {classifier_log} 2>/dev/null || true", capture=True)
        print("-------------------- Classifier Error Log --------------------")
        print(err_log if err_log else "<No output captured in classifier.log>")
        print("--------------------------------------------------------------")
        stop_pktgen(args.client)
        cleanup_server(args.server, args.server_ifname)
        rate_limit = getattr(args, "rate_limit", 0)
        expected_pps = INTERVAL_CONFIGS.get(interval_us, {}).get("expected_pps", 0)
        eff_rate = min(expected_pps, rate_limit) if rate_limit > 0 else expected_pps
        return {
            "mode": mode,
            "ml_model": ml_model,
            "num_threads": num_threads,
            "interval_us": interval_us,
            "target_ratep": eff_rate,
            "mean_rxpps": 0.0,
            "std_rxpps": 0.0,
            "cpu_soft_pct": 0.0,
            "error": "Classifier startup failed"
        }
    elif ready_res.returncode != 0:
        print("    [!] Warning: Classifier startup timed out waiting for [CLASSIFIER_READY]. Continuing...")
    else:
        print("    [OK] Classifier attached to XDP and actively running.")

    # 4. Start client pktgen traffic
    client_workers = getattr(args, "client_threads", None) or num_threads
    print(f"[*] Starting client pktgen (Interval: {interval_us}us, DUT Threads: {num_threads}, Client Workers: {client_workers})...")
    rate_limit = getattr(args, "rate_limit", 0)
    start_pktgen(args.client, args.client_ifname, args.server_ip, args.server_mac, interval_us, num_threads=client_workers, rate_limit=rate_limit)
    time.sleep(1)

    # 5. Measure CPU utilization with mpstat on server for TEST_DURATION seconds
    # Monitor strictly the active cores assigned to the experiment to avoid dilution across all online cores
    print(f"[*] Monitoring execution for {args.duration} seconds via mpstat (cores {server_cpus})...")
    mpstat_cmd = f"mpstat -P {','.join(str(c) for c in server_cpus)} 1 {args.duration} -o JSON > {remote_logdir}/mpstat.json"
    ssh_exec(args.server, mpstat_cmd, check=False)

    # 6. Stop client pktgen first so no flood interrupts hit during shutdown, then stop classifier
    print("[*] Test completed. Cleaning up processes...")
    stop_pktgen(args.client)
    time.sleep(0.5)
    ssh_exec(args.server, f"if [ -f {pid_file} ]; then kill -SIGINT $(cat {pid_file}) 2>/dev/null || true; sleep 1.5; fi", check=False)
    cleanup_server(args.server, args.server_ifname)

    # 7. Download results from server (ensuring a clean local trial directory)
    local_trial_dir = Path(args.local_results_dir) / mode / ml_model / f"{num_threads}threads" / f"u{interval_us}"
    if local_trial_dir.exists():
        import shutil
        shutil.rmtree(local_trial_dir)
    local_trial_dir.mkdir(parents=True, exist_ok=True)
    
    scp_cmd = f"scp -r {args.server}:{remote_logdir}/* {local_trial_dir}/"
    subprocess.run(scp_cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    # 8. Parse trial throughput summary
    # Extract candidate rate series from both rxpps.log and classifier.log.
    # Unbuffered stdout (classifier.log) is streamed in real-time every second,
    # making it resilient against process-exit truncations that can affect rxpps.log.
    rxpps_file = local_trial_dir / "rxpps.log"
    classifier_log_file = local_trial_dir / "classifier.log"
    mean_rx, std_rx = 0.0, 0.0
    
    rx_rates = []
    if rxpps_file.exists():
        try:
            rx_rates = [
                float(line.strip())
                for line in rxpps_file.read_text().splitlines()
                if line.strip().replace('.', '', 1).isdigit()
            ]
        except Exception as e:
            print(f"[!] Warning: Could not parse rxpps.log: {e}")

    c_rates = []
    if classifier_log_file.exists():
        try:
            for line in classifier_log_file.read_text().splitlines():
                parts = line.strip().split()
                if parts and parts[-1].isdigit():
                    c_rates.append(float(parts[-1]))
        except Exception as e:
            print(f"[!] Warning: Could not parse classifier.log: {e}")

    # Select the most complete time series:
    # If classifier.log has more samples than rxpps.log, prioritize it to avoid
    # truncated or stale partial writes from rxpps.log.
    if len(c_rates) >= len(rx_rates) and len(c_rates) > 0:
        rates = c_rates
        if rx_rates and len(rx_rates) < len(c_rates):
            print(f"    [*] Notice: Prioritizing complete classifier.log ({len(c_rates)} samples) over truncated rxpps.log ({len(rx_rates)} samples).")
    else:
        rates = rx_rates

    if rates:
        # Discard first 2 warmup seconds
        valid_rates = rates[2:] if len(rates) > 2 else rates
        import statistics
        mean_rx = statistics.mean(valid_rates)
        std_rx = statistics.stdev(valid_rates) if len(valid_rates) > 1 else 0.0
    else:
        print(f"[!] Warning: No throughput rates could be extracted from rxpps.log or classifier.log.")
        if classifier_log_file.exists():
            log_lines = classifier_log_file.read_text().splitlines()
            print(f"    [Diagnostic] classifier.log tail ({len(log_lines)} lines):")
            for l in log_lines[-10:]:
                print(f"      {l}")
        if rxpps_file.exists():
            rx_lines = rxpps_file.read_text().splitlines()
            print(f"    [Diagnostic] rxpps.log content ({len(rx_lines)} lines): {rx_lines[:5]}")
        else:
            print(f"    [Diagnostic] rxpps.log does not exist.")

    # 9. Parse CPU softirq usage from mpstat.json, strictly filtering and averaging active server_cpus
    cpu_soft = 0.0
    per_core_info = ""
    mpstat_file = local_trial_dir / "mpstat.json"
    if mpstat_file.exists():
        try:
            mp_data = json.loads(mpstat_file.read_text())
            hosts = mp_data.get("sysstat", {}).get("hosts", [])
            if hosts:
                stats = hosts[0].get("statistics", [])
                target_cpu_strs = {str(c) for c in server_cpus}
                sec_averages = []
                per_core_soft = {str(c): [] for c in server_cpus}

                for entry in stats:
                    sec_core_vals = []
                    for c_load in entry.get("cpu-load", []):
                        c_id = str(c_load.get("cpu"))
                        if c_id in target_cpu_strs:
                            val = float(c_load.get("soft", 0.0))
                            sec_core_vals.append(val)
                            per_core_soft[c_id].append(val)
                    if sec_core_vals:
                        sec_averages.append(sum(sec_core_vals) / len(sec_core_vals))

                if sec_averages:
                    cpu_soft = sum(sec_averages) / len(sec_averages)

                # Format per-core breakdown string (only for the target cores under test)
                active_cores_summary = []
                for c in server_cpus:
                    c_str = str(c)
                    vals = per_core_soft.get(c_str, [])
                    if vals:
                        active_cores_summary.append(f"CPU{c}: {sum(vals)/len(vals):.1f}%")
                if active_cores_summary:
                    per_core_info = " (" + ", ".join(active_cores_summary) + ")"
        except Exception as e:
            print(f"[!] Warning: Could not parse mpstat.json: {e}")

    print(f"[+] Result: RX Throughput: {mean_rx:,.0f} pps (std: {std_rx:,.0f}) | CPU SoftIRQ: {cpu_soft:.1f}%{per_core_info}")
    time.sleep(args.cooldown)

    expected_pps = INTERVAL_CONFIGS.get(interval_us, {}).get("expected_pps", 0)
    eff_rate = min(expected_pps, rate_limit) if rate_limit > 0 else expected_pps
    return {
        "mode": mode,
        "ml_model": ml_model,
        "num_threads": num_threads,
        "interval_us": interval_us,
        "target_ratep": eff_rate,
        "mean_rxpps": mean_rx,
        "std_rxpps": std_rx,
        "cpu_soft_pct": cpu_soft
    }

# ==============================================================================
# MAIN ENTRYPOINT
# ==============================================================================
def main():
    parser = argparse.ArgumentParser(description="Automated Stage II Test Orchestrator (Hara & Sasabe Replication)")
    parser.add_argument("--client", default=DEFAULT_CLIENT_HOST, help="Client SSH host alias")
    parser.add_argument("--server", default=DEFAULT_SERVER_HOST, help="Server SSH host alias")
    parser.add_argument("--client-ifname", default=DEFAULT_CLIENT_IFNAME, help="Client X710 interface name")
    parser.add_argument("--server-ifname", default=DEFAULT_SERVER_IFNAME, help="Server X710 interface name")
    parser.add_argument("--server-ip", default=DEFAULT_SERVER_IP, help="Destination Server IP")
    parser.add_argument("--server-mac", default=DEFAULT_SERVER_MAC, help="Destination Server MAC")
    parser.add_argument("--server-repo-path", default=DEFAULT_SERVER_REPO_PATH, help="Path to ebpf-classifier on Server")
    parser.add_argument("--local-results-dir", default=DEFAULT_LOCAL_RESULTS_DIR, help="Local results destination")
    parser.add_argument("--duration", type=int, default=DEFAULT_TEST_DURATION, help="Duration in seconds per trial")
    parser.add_argument("--cooldown", type=int, default=DEFAULT_COOLDOWN, help="Cooldown in seconds between runs")
    
    # Test sweep selections
    parser.add_argument("--modes", nargs="+", default=["xdp_drv"], 
                        choices=["xdp_drv", "xdp_skb", "tc", "userspace"],
                        help="Modes to test (default: xdp_drv)")
    parser.add_argument("--models", nargs="+", default=["dt", "filter"],
                        choices=["dt", "filter", "nn"],
                        help="Models to test (default: dt, filter)")
    parser.add_argument("--threads", nargs="+", type=int, default=[1],
                        help="Thread / Core counts to test (default: 1)")
    parser.add_argument("--client-threads", type=int, default=None,
                        help="Number of pktgen worker threads on Client (default: matches --threads count)")
    parser.add_argument("--offline-cpus", action="store_true", default=False,
                        help="Dynamically offline unused CPUs via chcpu (default: False; keep False on baremetal to prevent APIC vector exhaustion)")
    parser.add_argument("--rate-limit", type=int, default=0,
                        help="Optional artificial rate limit in pps (default: 0 = unconstrained 10GbE wire speed; set to 800000 for legacy paper comparison)")
    parser.add_argument("--intervals", nargs="+", type=int, default=[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
                        help="Packet sending intervals in us (default: 0 through 10)")
    parser.add_argument("--quick", action="store_true", 
                        help="Fast smoke test mode (5s duration, intervals 0 and 5)")
    parser.add_argument("--sync", action="store_true", default=True,
                        help="Sync local classifier scripts to server before running (default: True)")
    parser.add_argument("--no-sync", dest="sync", action="store_false",
                        help="Do not sync local files to server")

    args = parser.parse_args()
    args.local_results_dir = ensure_writable_results_dir(args.local_results_dir)

    if args.quick:
        args.duration = 7
        args.intervals = [0, 5]
        print("[!] QUICK SMOKE TEST MODE ACTIVATED (7s per test, limited intervals)")

    # Pre-flight check: ensure SSH connections work, check dependencies, and display NUMA topology
    print("[*] Pre-flight check: Testing SSH connections & remote environment...")
    try:
        c_uname = ssh_exec(args.client, "uname -r", capture=True)
        s_uname = ssh_exec(args.server, "uname -r", capture=True)
        print(f"    [OK] Client ({args.client}) Kernel: {c_uname}")
        print(f"    [OK] Server ({args.server}) Kernel: {s_uname}")

        # Check Python environment on Server
        server_env_probe = (
            "python3 -c \""
            "import bcc; "
            "import numpy; "
            "print('bcc and numpy are verified')"
            "\" 2>&1"
        )
        probe_res = ssh_exec(args.server, server_env_probe, check=False, capture=True)
        if probe_res and "No module named 'numpy'" in probe_res:
            print("    [!] Warning: 'numpy' is NOT installed on server! Run 'dnf install -y python3-numpy' on server.")
        elif probe_res and "No module named 'bcc'" in probe_res:
            print("    [!] Warning: 'bcc' is NOT installed on server! Run 'dnf install -y bcc-tools python3-bcc' on server.")
        else:
            print(f"    [OK] Server Python environment: bcc and numpy verified.")

        # Probe NUMA topology on Client and Server
        c_node = ssh_exec(args.client, f"cat /sys/class/net/{args.client_ifname}/device/numa_node 2>/dev/null || echo 0", capture=True)
        s_node = ssh_exec(args.server, f"cat /sys/class/net/{args.server_ifname}/device/numa_node 2>/dev/null || echo 0", capture=True)
        max_threads = max(args.threads) if args.threads else 1
        c_cpus = get_remote_numa_cpus(args.client, args.client_ifname, count=max_threads)
        s_cpus = get_remote_numa_cpus(args.server, args.server_ifname, count=max_threads)
        print(f"    [OK] Client ({args.client}) NIC '{args.client_ifname}': NUMA Node {c_node} | Socket CPUs: {c_cpus}")
        print(f"    [OK] Server ({args.server}) NIC '{args.server_ifname}': NUMA Node {s_node} | Socket CPUs: {s_cpus}")
    except Exception as e:
        print(f"[!] Pre-flight SSH check failed: {e}")
        print("    Please ensure 'ssh client' and 'ssh server' work passwordlessly from this machine.")
        sys.exit(1)

    # Sync scripts to server if enabled
    if args.sync:
        sync_code_to_server(args)

    # Ensure all server cores are online before starting the test matrix
    restore_server_cores(args.server)

    all_results = []
    total_tests = len(args.threads) * len(args.modes) * len(args.models) * len(args.intervals)
    current_test = 0

    print(f"[*] Starting test matrix: {total_tests} total trials planned.")

    try:
        for th in args.threads:
            for mode in args.modes:
                for model in args.models:
                    for interval in args.intervals:
                        current_test += 1
                        print(f"\n[Progress: {current_test}/{total_tests}]")
                        res = run_single_trial(args, mode, model, th, interval)
                        all_results.append(res)
    except KeyboardInterrupt:
        print("\n[!] Execution interrupted by user! Stopping active processes...")
    finally:
        stop_pktgen(args.client)
        cleanup_server(args.server, args.server_ifname)
        restore_server_cores(args.server)

    # Save summary CSV
    csv_file = Path(args.local_results_dir) / "summary_stage2.csv"
    if all_results:
        import csv
        keys = all_results[0].keys()
        with open(csv_file, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=keys)
            writer.writeheader()
            writer.writerows(all_results)
        print(f"\n[✓] All tests finished! Summary results saved to: {csv_file}")
    else:
        print("\n[!] No results collected.")

if __name__ == "__main__":
    main()
