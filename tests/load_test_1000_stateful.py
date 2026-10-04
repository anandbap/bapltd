#!/usr/bin/env python3
"""
BAP Control Plane: 1,000 Stateful Concurrent Connections Stress Test & Live Dashboard Stream

Usage:
  python tests/load_test_1000_stateful.py
  python tests/load_test_1000_stateful.py --url https://localhost:8443 --sessions 1000 --duration 600
  python tests/load_test_1000_stateful.py --no-teardown  # Keeps agents active in UI after run

Features:
1. Connects to existing Control Plane (https://localhost:8443 or http://localhost:8080) or auto-starts one.
2. Automatically opens the CIO Cockpit dashboard (https://localhost:8443/dashboard/) in the browser.
3. Ramps up 1,000 stateful agent sessions with distinct identities, owners, and mission intents.
4. Sustains continuous keep-alive heartbeats (~200 req/sec) and periodic telemetry ingestion.
5. Continuously measures latency percentiles, error rates, and control plane CPU/RAM utilization.
6. Cryptographically verifies the SHA-256 Merkle audit chain at test completion.
"""

import argparse
import asyncio
import aiohttp
import json
import os
import psutil
import random
import socket
import ssl
import subprocess
import sys
import time
import urllib.request
import webbrowser

INTENT_CHOICES = [
    ("BUG_FIX", "Fix null pointer exception in invoice parser"),
    ("FEATURE_ENHANCEMENT", "Add multi-currency support to checkout flow"),
    ("DATABASE_CHANGE", "Run database migration for user preferences table"),
    ("INVESTIGATION", "Investigate high latency in payment gateway webhooks"),
    ("REFACTOR", "Refactor authentication middleware to use bearer token validator"),
    ("TEST_VERIFICATION", "Run end-to-end integration test suite on billing service"),
]

def compute_percentiles(samples_ms):
    if not samples_ms:
        return {"min": 0, "p50": 0, "p90": 0, "p95": 0, "p99": 0, "max": 0, "mean": 0}
    sorted_s = sorted(samples_ms)
    n = len(sorted_s)
    def p(pct):
        idx = int(round((pct / 100.0) * (n - 1)))
        return sorted_s[min(max(idx, 0), n - 1)]
    return {
        "min": round(sorted_s[0], 2),
        "p50": round(p(50), 2),
        "p90": round(p(90), 2),
        "p95": round(p(95), 2),
        "p99": round(p(99), 2),
        "max": round(sorted_s[-1], 2),
        "mean": round(sum(sorted_s) / n, 2),
    }

def check_url_health(url):
    ctx = ssl._create_unverified_context()
    try:
        with urllib.request.urlopen(f"{url.rstrip('/')}/api/v1/health", context=ctx, timeout=1.5) as resp:
            return resp.status == 200
    except Exception:
        return False

class LoadTestMetrics:
    def __init__(self):
        self.heartbeat_latencies = []
        self.inspector_latencies = []
        self.event_latencies = []
        self.heartbeats_ok = 0
        self.heartbeats_err = 0
        self.events_ok = 0
        self.events_err = 0
        self.inspector_ok = 0
        self.inspector_err = 0
        self.active_sessions = set()
        self.cpu_samples = []
        self.ram_samples = []
        self.lock = asyncio.Lock()

    async def record_heartbeat(self, latency_ms, success):
        async with self.lock:
            self.heartbeat_latencies.append(latency_ms)
            if success:
                self.heartbeats_ok += 1
            else:
                self.heartbeats_err += 1

    async def record_inspector(self, latency_ms, success):
        async with self.lock:
            self.inspector_latencies.append(latency_ms)
            if success:
                self.inspector_ok += 1
            else:
                self.inspector_err += 1

    async def record_event(self, latency_ms, success):
        async with self.lock:
            self.event_latencies.append(latency_ms)
            if success:
                self.events_ok += 1
            else:
                self.events_err += 1

async def agent_worker(agent_idx, base_url, session, metrics, stop_event, heartbeat_interval, no_teardown):
    session_id = f"sess-load-{agent_idx:04d}"
    instance_id = f"node-{agent_idx:04d}"
    app_id = "governed-agent-worker"
    user_id = f"developer-{agent_idx % 50 + 1:02d}"
    user_email = f"{user_id}@enterprise.internal"
    spiffe_id = f"spiffe://bap.internal/app/{app_id}/instance/{instance_id}"
    intent_cat, intent_prompt = INTENT_CHOICES[agent_idx % len(INTENT_CHOICES)]

    # 1. Register and start session
    start_payload = {
        "session_id": session_id,
        "app_id": app_id,
        "instance_id": instance_id,
        "agent_name": f"Agent-{agent_idx:04d}",
        "user_id": user_id,
        "user_email": user_email,
        "spiffe_id": spiffe_id,
        "hostname": f"workstation-{agent_idx % 100 + 1:03d}",
        "user_prompt": intent_prompt,
        "intent": {
            "primary": intent_cat,
            "confidence": 0.95,
            "source": "claude-user-prompt-submit",
            "prompt_captured": True
        }
    }

    try:
        async with session.post(f"{base_url}/api/v1/sessions/start", json=start_payload, timeout=aiohttp.ClientTimeout(total=5)) as resp:
            if resp.status == 200:
                metrics.active_sessions.add(session_id)
            else:
                return
    except Exception:
        return

    # Initial stagger to desynchronize heartbeats across the fleet
    await asyncio.sleep(random.uniform(0.1, 5.0))

    pulse_count = 0
    while not stop_event.is_set():
        t0 = time.perf_counter()
        hb_payload = {"session_id": session_id}
        try:
            async with session.post(f"{base_url}/api/v1/sessions/heartbeat", json=hb_payload, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                lat = (time.perf_counter() - t0) * 1000.0
                await metrics.record_heartbeat(lat, resp.status == 200)
        except Exception:
            lat = (time.perf_counter() - t0) * 1000.0
            await metrics.record_heartbeat(lat, False)

        pulse_count += 1

        # Stochastic audit telemetry emission (~4% of pulses)
        if random.random() < 0.04:
            ev_t0 = time.perf_counter()
            audit_batch = [{
                "event_id": f"ev-{session_id}-{pulse_count}",
                "session_id": session_id,
                "source": "agent-worker",
                "executable": "git",
                "full_command": f"git status --porcelain (action {pulse_count})",
                "decision": "allow",
                "duration_ms": 2,
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            }]
            try:
                async with session.post(f"{base_url}/api/v1/audit/ingest", json=audit_batch, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                    ev_lat = (time.perf_counter() - ev_t0) * 1000.0
                    await metrics.record_event(ev_lat, resp.status == 200)
            except Exception:
                ev_lat = (time.perf_counter() - ev_t0) * 1000.0
                await metrics.record_event(ev_lat, False)

        # Cadence with minor random jitter
        jitter = random.uniform(-0.5, 0.5)
        sleep_dur = max(1.0, heartbeat_interval + jitter)
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=sleep_dur)
            break
        except asyncio.TimeoutError:
            pass

    # Clean teardown (unless --no-teardown was requested so user can explore them in UI)
    if not no_teardown:
        try:
            end_payload = {"session_id": session_id, "reason": "load_test_complete"}
            await session.post(f"{base_url}/api/v1/sessions/end", json=end_payload, timeout=aiohttp.ClientTimeout(total=3))
        except Exception:
            pass

async def cockpit_inspector_poller(base_url, session, metrics, stop_event):
    """Simulates the CIO Cockpit dashboard polling aggregated telemetry every 2 seconds."""
    while not stop_event.is_set():
        t0 = time.perf_counter()
        try:
            async with session.get(f"{base_url}/api/v1/inspector/data", timeout=aiohttp.ClientTimeout(total=5)) as resp:
                lat = (time.perf_counter() - t0) * 1000.0
                await metrics.record_inspector(lat, resp.status == 200)
        except Exception:
            lat = (time.perf_counter() - t0) * 1000.0
            await metrics.record_inspector(lat, False)

        try:
            await asyncio.wait_for(stop_event.wait(), timeout=2.0)
            break
        except asyncio.TimeoutError:
            pass

async def telemetry_monitor(cp_process, base_url, session, metrics, stop_event, start_time, total_duration, report_interval, target_sessions):
    """Samples control plane CPU/RAM and logs progressive metrics every report_interval seconds."""
    p = None
    if cp_process:
        try:
            p = psutil.Process(cp_process.pid)
            p.cpu_percent(interval=None)
        except Exception:
            p = None

    while not stop_event.is_set():
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=report_interval)
            break
        except asyncio.TimeoutError:
            pass

        elapsed = int(time.time() - start_time)
        cpu = 0.0
        rss_mb = 0.0
        threads = 0
        if p:
            try:
                cpu = p.cpu_percent(interval=None)
                mem_info = p.memory_info()
                rss_mb = mem_info.rss / (1024 * 1024)
                threads = p.num_threads()
                metrics.cpu_samples.append(cpu)
                metrics.ram_samples.append(rss_mb)
            except Exception:
                pass

        # Query active session count from control plane
        cp_sessions_count = -1
        try:
            async with session.get(f"{base_url}/api/v1/inspector/data", timeout=aiohttp.ClientTimeout(total=3)) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    sessions = data.get("sessions", [])
                    active_list = [s for s in sessions if s.get("status") == "active"]
                    cp_sessions_count = len(active_list)
        except Exception:
            pass

        # Compute rolling window latency
        recent_hb = metrics.heartbeat_latencies[-2000:] if metrics.heartbeat_latencies else []
        hb_stats = compute_percentiles(recent_hb)
        recent_insp = metrics.inspector_latencies[-15:] if metrics.inspector_latencies else []
        insp_stats = compute_percentiles(recent_insp)

        mins = elapsed // 60
        secs = elapsed % 60
        resource_str = f"CP CPU: {cpu:>4.1f}% | RAM: {rss_mb:>5.1f}MB" if p else "Running on external service"
        print(f"[{mins:02d}:{secs:02d}] "
              f"Active in UI: {cp_sessions_count:>4d}/{target_sessions} | "
              f"HBs: {metrics.heartbeats_ok:>6d} (err: {metrics.heartbeats_err}) | "
              f"HB p50: {hb_stats['p50']:>4.1f}ms, p95: {hb_stats['p95']:>5.1f}ms | "
              f"Cockpit p50: {insp_stats['p50']:>4.1f}ms | "
              f"{resource_str}")

async def run_load_test(args):
    root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    cp_bin = os.path.join(root_dir, "bapcontrolplane.exe")

    target_url = args.url.rstrip("/") if args.url else None
    auto_started_proc = None

    # Step 1: Detect or Start Control Plane
    if not target_url:
        if check_url_health("https://localhost:8443"):
            target_url = "https://localhost:8443"
            print("[+] Discovered active Control Plane on https://localhost:8443")
        elif check_url_health("http://localhost:8080"):
            target_url = "http://localhost:8080"
            print("[+] Discovered active Control Plane on http://localhost:8080")
        else:
            print("[*] No active Control Plane detected. Starting bapcontrolplane on https://localhost:8443...")
            auto_started_proc = subprocess.Popen(
                [cp_bin, "-port", "8443", "-https", "-trust-domain", "bap.internal", "-demo-mode=false"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            target_url = "https://localhost:8443"
            for _ in range(40):
                if check_url_health(target_url):
                    break
                time.sleep(0.2)
            else:
                print("[!] Failed to auto-start Control Plane on port 8443.")
                sys.exit(1)
            print("[+] Control Plane initialized successfully on https://localhost:8443")
    else:
        if not check_url_health(target_url):
            print(f"[*] Starting bapcontrolplane on {target_url}...")
            port = 8443 if "8443" in target_url else 8080
            use_https = target_url.startswith("https")
            cmd = [cp_bin, "-port", str(port)]
            if use_https:
                cmd.append("-https")
            auto_started_proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            for _ in range(40):
                if check_url_health(target_url):
                    break
                time.sleep(0.2)
            else:
                print(f"[!] Target {target_url} is unreachable.")
                sys.exit(1)

    dashboard_url = f"{target_url}/dashboard/"

    print("=" * 80)
    print(f"      BAP CONTROL PLANE - {args.sessions:,} STATEFUL AGENT CONNECTIONS BENCHMARK")
    print("=" * 80)
    print(f"[*] Target Endpoint    : {target_url}")
    print(f"[*] CIO Cockpit UI     : {dashboard_url}")
    print(f"[*] Concurrent Workers : {args.sessions} stateful agent connections")
    print(f"[*] Duration           : {args.duration} seconds ({args.duration/60:.1f} minutes)")
    print(f"[*] Heartbeat Cadence  : Every ~{args.interval}s (~{int(args.sessions/args.interval)} req/sec sustained)")
    print(f"[*] Teardown on Exit   : {'Disabled (--no-teardown, agents remain active in UI)' if args.no_teardown else 'Graceful cleanup'}")
    print("=" * 80)

    # Automatically open the browser to the dashboard if requested
    if args.open_browser:
        print(f"[*] Opening browser to CIO Cockpit: {dashboard_url}")
        try:
            webbrowser.open(dashboard_url)
        except Exception:
            pass

    metrics = LoadTestMetrics()
    stop_event = asyncio.Event()

    # Configure high-capacity connector with unverified SSL context for self-signed localhost HTTPS
    connector = aiohttp.TCPConnector(
        limit=max(args.sessions + 200, 1500),
        limit_per_host=max(args.sessions + 200, 1500),
        keepalive_timeout=60,
        enable_cleanup_closed=True,
        ssl=False
    )

    start_time = time.time()

    async with aiohttp.ClientSession(connector=connector) as session:
        ramp_batch = 50
        print(f"[*] Ramping up {args.sessions} stateful agent connections (staggered ~{ramp_batch}/s)...")
        tasks = []
        for i in range(1, args.sessions + 1):
            tasks.append(asyncio.create_task(agent_worker(i, target_url, session, metrics, stop_event, args.interval, args.no_teardown)))
            if i % ramp_batch == 0:
                await asyncio.sleep(1.0)

        print(f"[+] All {args.sessions} agent workers spawned. Streaming live into the dashboard...")
        print("-" * 80)
        print(" TIME     SESSIONS IN UI    HEARTBEATS             LATENCY              COCKPIT    SYSTEM RESOURCE")
        print("-" * 80)

        # Cockpit poller task
        inspector_task = asyncio.create_task(cockpit_inspector_poller(target_url, session, metrics, stop_event))
        # Telemetry monitor task
        monitor_task = asyncio.create_task(
            telemetry_monitor(auto_started_proc, target_url, session, metrics, stop_event, start_time, args.duration, args.report_interval, args.sessions)
        )

        try:
            await asyncio.sleep(args.duration)
        except asyncio.CancelledError:
            pass

        print("-" * 80)
        print(f"[*] Test duration completed ({args.duration}s). Signaling teardown...")
        stop_event.set()

        await asyncio.gather(*tasks, return_exceptions=True)
        await asyncio.gather(inspector_task, monitor_task, return_exceptions=True)

    # Final verification
    print("\n[*] Performing final audit integrity and session consistency verification...")
    chain_valid = False
    total_events = 0
    final_active_count = 0
    ctx = ssl._create_unverified_context()
    try:
        with urllib.request.urlopen(f"{target_url}/api/v1/control/chain/verify", context=ctx, timeout=5) as resp:
            v_data = json.loads(resp.read().decode())
            chain_valid = v_data.get("valid", False)
            total_events = v_data.get("total_events", 0)
    except Exception as e:
        print(f"[!] Chain verify error: {e}")

    try:
        with urllib.request.urlopen(f"{target_url}/api/v1/inspector/data", context=ctx, timeout=5) as resp:
            s_data = json.loads(resp.read().decode())
            final_active_count = len([s for s in s_data.get("sessions", []) if s.get("status") == "active"])
    except Exception as e:
        pass

    # If we auto-started the process and not leaving running, terminate it
    if auto_started_proc and not args.no_teardown:
        auto_started_proc.terminate()
        try:
            auto_started_proc.wait(timeout=3)
        except Exception:
            auto_started_proc.kill()
    elif auto_started_proc and args.no_teardown:
        print(f"[+] Control Plane remains active on {target_url} for live inspection in browser.")

    # Print Final Benchmark Summary
    hb_all = compute_percentiles(metrics.heartbeat_latencies)
    insp_all = compute_percentiles(metrics.inspector_latencies)
    avg_cpu = round(sum(metrics.cpu_samples) / max(len(metrics.cpu_samples), 1), 2) if metrics.cpu_samples else "N/A"
    max_ram = round(max(metrics.ram_samples), 2) if metrics.ram_samples else "N/A"
    min_ram = round(min(metrics.ram_samples), 2) if metrics.ram_samples else "N/A"
    total_reqs = metrics.heartbeats_ok + metrics.heartbeats_err + metrics.events_ok + metrics.events_err + metrics.inspector_ok + metrics.inspector_err
    success_rate = round(((metrics.heartbeats_ok + metrics.events_ok + metrics.inspector_ok) / max(total_reqs, 1)) * 100.0, 3)

    print()
    print("=" * 80)
    print(f"                 {args.sessions:,} STATEFUL CONNECTIONS BENCHMARK RESULTS")
    print("=" * 80)
    print(f" Total Test Duration         : {args.duration} seconds ({args.duration/60:.1f} minutes)")
    print(f" Concurrent Stateful Agents  : {args.sessions}")
    print(f" Active Workloads in UI      : {final_active_count} active")
    print(f" Total HTTP Requests Handled : {total_reqs:,}")
    print(f" Overall Request Success Rate: {success_rate}%")
    print(f" Total Heartbeats Delivered  : {metrics.heartbeats_ok:,} (Errors: {metrics.heartbeats_err})")
    print(f" Telemetry Events Ingested   : {metrics.events_ok:,} (Errors: {metrics.events_err})")
    print(f" Cockpit Polls Completed     : {metrics.inspector_ok:,} (Errors: {metrics.inspector_err})")
    print()
    print(f" Latency Percentiles (Heartbeats):")
    print(f"   min  = {hb_all['min']:>6.2f} ms | p50 = {hb_all['p50']:>6.2f} ms | p90 = {hb_all['p90']:>6.2f} ms")
    print(f"   p95  = {hb_all['p95']:>6.2f} ms | p99 = {hb_all['p99']:>6.2f} ms | max = {hb_all['max']:>6.2f} ms | mean = {hb_all['mean']:>6.2f} ms")
    print()
    print(f" Latency Percentiles (CIO Cockpit Inspector):")
    print(f"   p50  = {insp_all['p50']:>6.2f} ms | p95 = {insp_all['p95']:>6.2f} ms | p99 = {insp_all['p99']:>6.2f} ms | mean = {insp_all['mean']:>6.2f} ms")
    print()
    print(f" Control Plane Resource Footprint:")
    print(f"   Average CPU Utilization   : {avg_cpu}%" if avg_cpu != "N/A" else "   Average CPU Utilization   : Monitored via host")
    print(f"   RAM Footprint Range       : {min_ram} MB -> {max_ram} MB" if max_ram != "N/A" else "   RAM Footprint Range       : Monitored via host")
    print(f"   SHA-256 Merkle Chain Valid: {'YES (100% Intact)' if chain_valid else 'VERIFICATION ERROR'}")
    print(f"   Dashboard Link            : {dashboard_url}")
    print("=" * 80)

def parse_args():
    parser = argparse.ArgumentParser(description="BAP Control Plane: 1,000 Stateful Connections Benchmark & Live UI Stream")
    parser.add_argument("--url", default="", help="Control plane URL (defaults to auto-discovering https://localhost:8443 or starting one)")
    parser.add_argument("--sessions", type=int, default=1000, help="Number of concurrent stateful sessions (default: 1000)")
    parser.add_argument("--duration", type=int, default=600, help="Duration in seconds (default: 600 = 10 minutes)")
    parser.add_argument("--interval", type=float, default=5.0, help="Heartbeat interval in seconds (default: 5.0)")
    parser.add_argument("--report-interval", type=int, default=30, help="Progress reporting interval in seconds (default: 30)")
    parser.add_argument("--no-teardown", action="store_true", help="Keep sessions active in dashboard at completion")
    parser.add_argument("--no-browser", action="store_true", help="Do not automatically open browser")
    args = parser.parse_args()
    args.open_browser = not args.no_browser
    return args

if __name__ == "__main__":
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
    args = parse_args()
    try:
        asyncio.run(run_load_test(args))
    except KeyboardInterrupt:
        print("\n[*] Benchmark interrupted by user.")
