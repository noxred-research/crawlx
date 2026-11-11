#!/usr/bin/python3 -I
"""Deterministic helper fixtures; optional real privileged and rootless Chromium acceptance.

Run unit fixtures: python3 -I deploy/isolation/test_netns_helper.py

Rootless real proof (ordinary user; no root, no sudo):
  CRAWLX_RUN_NETNS_ROOTLESS_ACCEPTANCE=1 CRAWLX_CHROMIUM_PATH=/absolute/chromium \
    python3 -I deploy/isolation/test_netns_helper.py RootlessAcceptance
  Optional CRAWLX_NETNS_BROWSER_UID/GID select the namespace-internal browser
  identity (default 1000; must lie in 1..65534).
  Requires user namespaces, /etc/subuid and /etc/subgid ranges for the current
  user, newuidmap/newgidmap, nsenter, and the helper's fixed executables.

Privileged real proof (root, namespace/nft privileges):
  CRAWLX_RUN_NETNS_ACCEPTANCE=1 CRAWLX_CHROMIUM_PATH=/absolute/chromium
    CRAWLX_NETNS_BROWSER_UID=1000 CRAWLX_NETNS_BROWSER_GID=1000 python3 -I ...
  Requires a working Chromium sandbox.

Missing prerequisites fail the opted-in test; they are never reported as a
passing proof.
"""

import argparse
import http.client
import http.server
import importlib.util
import json
import os
import select
import signal
import socket
import subprocess
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("crawlx_namespace_helper", HERE / "crawlx-netns-helper.py")
HELPER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HELPER)

NSENTER = "/usr/bin/nsenter"
ROOTLESS_MAPS = ([(0, 1000, 1), (1, 524288, 65535)], [(0, 1000, 1), (1, 524288, 65535)])


def browser_args(profile, isolation="privileged", uid=1000, gid=1000, port=8080):
    return argparse.Namespace(
        isolation=isolation, uid=uid, gid=gid, proxy_port=port, profile=profile,
        command=["/missing/chromium", "--headless=new", "--remote-debugging-port=0",
                 "--user-data-dir=" + profile, f"--proxy-server=http://127.0.0.1:{port}"])


class NegativeFixtures(unittest.TestCase):
    def test_exact_firewall_normalization_and_extra_rules(self):
        expected = HELPER.firewall_snapshot(8080, 9222)
        entries = [{"metainfo": {"version": "fixture"}}]
        for entry in expected:
            kind, value = next(iter(entry.items()))
            entries.append({kind: dict(value, handle=1)})
        self.assertEqual(HELPER.canonical_firewall({"nftables": entries}), expected)
        entries.append({"rule": {"family": "inet", "table": "crawlx", "chain": "output",
                                  "expr": [{"accept": None}]}})
        self.assertNotEqual(HELPER.canonical_firewall({"nftables": entries}), expected)
        with self.assertRaises(ValueError):
            HELPER.canonical_firewall({"nftables": [{"set": {"name": "bypass"}}]})

    def test_default_route_and_non_loopback_interface_are_rejected(self):
        responses = [[{"ifname": "lo"}], [{"dst": "default", "dev": "lo"}]]
        with patch.object(HELPER, "read_json", side_effect=responses):
            with self.assertRaises(ValueError):
                HELPER.topology()
        with patch.object(HELPER, "read_json", return_value=[{"ifname": "lo"}, {"ifname": "eth0"}]):
            with self.assertRaises(ValueError):
                HELPER.topology()

    def test_root_browser_and_unmanaged_proxy_are_rejected(self):
        with tempfile.TemporaryDirectory() as profile:
            args = browser_args(profile)
            HELPER.validate_args(args)
            args.uid = 0
            with self.assertRaises(ValueError):
                HELPER.validate_args(args)
            args.uid = 1000
            args.command[-1] = "--proxy-server=http://192.0.2.1:8080"
            with self.assertRaises(ValueError):
                HELPER.validate_args(args)

    def test_rootless_browser_identity_is_confined_to_the_subordinate_range(self):
        with tempfile.TemporaryDirectory() as profile:
            args = browser_args(profile, "rootless", 1, 1)
            HELPER.validate_args(args)
            for uid, gid in ((0, 1), (1, 0), (65535, 1), (1, 65535), (4294967294, 1)):
                args.uid, args.gid = uid, gid
                with self.assertRaises(ValueError):
                    HELPER.validate_args(args)
            args.uid = args.gid = 1
            args.command.append("--no-sandbox")
            with self.assertRaises(ValueError):
                HELPER.validate_args(args)

    def test_rootless_identity_proves_distinct_subordinate_browser(self):
        uid_map, gid_map = ROOTLESS_MAPS
        self.assertEqual(HELPER.rootless_identity(uid_map, gid_map, 1000, 1000, 1000, 1000),
                         (524288 + 999, 524288 + 999))
        self.assertEqual(HELPER.rootless_identity(uid_map, gid_map, 1000, 1000, 1, 65534),
                         (524288, 524288 + 65533))

    def test_rootless_identity_rejects_aliasing_unmapped_and_foreign_roots(self):
        uid_map, gid_map = ROOTLESS_MAPS
        cases = {
            "browser root": (uid_map, gid_map, 1000, 1000, 0, 1),
            "unmapped uid": (uid_map, gid_map, 1000, 1000, 70000, 1),
            "unmapped gid": (uid_map, gid_map, 1000, 1000, 1, 70000),
            "root is not the worker": (uid_map, gid_map, 1001, 1000, 1, 1),
            "group root is not the worker": (uid_map, gid_map, 1000, 1001, 1, 1),
            "single-id map": ([(0, 1000, 1)], gid_map, 1000, 1000, 1, 1),
            "empty map": ([], gid_map, 1000, 1000, 1, 1),
            "browser maps to the worker": ([(0, 1000, 1), (1, 1000, 1)], gid_map, 1000, 1000, 1, 1),
            "range contains the worker": ([(0, 1000, 1), (1, 900, 200)], gid_map, 1000, 1000, 1, 1),
            "identity map": ([(0, 0, 4294967295)], gid_map, 0, 1000, 1, 1),
        }
        for name, case in cases.items():
            with self.subTest(name), self.assertRaises(ValueError):
                HELPER.rootless_identity(*case)

    def test_id_map_parser_reads_kernel_format(self):
        with tempfile.NamedTemporaryFile("w") as handle:
            handle.write("         0       1000          1\n         1     524288      65535\n")
            handle.flush()
            entries = HELPER.read_id_map(handle.name)
        self.assertEqual(entries, [(0, 1000, 1), (1, 524288, 65535)])
        self.assertEqual(HELPER.map_id(entries, 65535), 524288 + 65534)
        self.assertIsNone(HELPER.map_id(entries, 65536))

    def test_gate_status_proof_rejects_root_groups_caps_and_missing_no_new_privs(self):
        good = {"Uid:": ["5"] * 4, "Gid:": ["6"] * 4, "Groups:": [],
                "CapInh:": ["0000000000000000"], "CapPrm:": ["0000000000000000"],
                "CapEff:": ["0000000000000000"], "CapBnd:": ["0000000000000000"],
                "CapAmb:": ["0000000000000000"], "NoNewPrivs:": ["1"]}
        def check(values):
            with patch.object(HELPER, "status_value", side_effect=lambda _pid, key: values[key]):
                HELPER.verify_gate_identity(42, 5, 6)
        check(good)
        for key, bad in (("Uid:", ["5", "5", "0", "5"]), ("Gid:", ["6", "6", "6", "0"]),
                         ("Groups:", ["10"]), ("CapEff:", ["0000000000001000"]),
                         ("CapBnd:", ["000001ffffffffff"]), ("NoNewPrivs:", ["0"])):
            with self.subTest(key), self.assertRaises(ValueError):
                check(dict(good, **{key: bad}))

    def test_host_prerequisites_match_mode(self):
        with tempfile.TemporaryDirectory() as profile:
            with patch.object(HELPER.os, "geteuid", return_value=0):
                with self.assertRaisesRegex(ValueError, "refuses a root worker"):
                    HELPER.preflight_host(browser_args(profile, "rootless", 1, 1))
            with patch.object(HELPER.os, "geteuid", return_value=1000):
                with self.assertRaisesRegex(ValueError, "requires root"):
                    HELPER.preflight_host(browser_args(profile))
                with patch.object(HELPER.os.path, "isfile", return_value=False):
                    with self.assertRaisesRegex(ValueError, "isolation executable unavailable"):
                        HELPER.preflight_host(browser_args(profile, "rootless", 1, 1))

    def test_unshare_command_selects_user_namespace_only_for_rootless(self):
        rootless = HELPER.unshare_command(argparse.Namespace(isolation="rootless"))
        self.assertEqual(rootless[:6], [HELPER.UNSHARE, "--user", "--map-root-user",
                                         "--map-users=auto", "--map-groups=auto", "--net"])
        self.assertEqual(HELPER.unshare_command(argparse.Namespace(isolation="privileged")),
                         [HELPER.UNSHARE, "--net", "--"])

    def test_failure_text_is_actionable_and_never_echoes_arguments(self):
        failed = subprocess.CalledProcessError(
            1, [HELPER.MOUNT, "--bind", "/secret/arg"], stderr=b"mount: permission denied\n" + b"x" * 1000)
        text = HELPER.describe(failed)
        self.assertTrue(text.startswith("namespace helper rejected preflight: CalledProcessError: mount exit 1: "))
        self.assertNotIn("/secret/arg", text)
        self.assertLess(len(text), 400)
        self.assertIn("rootless namespace mode refuses a root worker",
                      HELPER.describe(ValueError("rootless namespace mode refuses a root worker")))
        self.assertEqual(HELPER.describe(OSError("secret")), "namespace helper rejected preflight: OSError")

    def test_gate_eof_never_execs_browser(self):
        result = subprocess.run([HELPER.PYTHON, "-I", str(HERE / "crawlx-netns-helper.py"),
                                 "gate", "/definitely-missing-browser"], input=b"",
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn(b"FileNotFoundError", result.stderr)

    def test_confine_refuses_without_namespace_root_and_never_mounts(self):
        result = subprocess.run([HELPER.PYTHON, "-I", str(HERE / "crawlx-netns-helper.py"),
                                 "confine", "1", "1", "/definitely-missing-profile", "--",
                                 "/definitely-missing-browser"], stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
        self.assertEqual(result.returncode, 1)
        if os.geteuid() != 0:
            self.assertIn(b"requires namespace root", result.stderr)

    def run_launch(self, *extra, profile=None):
        with tempfile.TemporaryDirectory() as directory:
            profile = profile or directory
            command = [HELPER.PYTHON, "-I", str(HERE / "crawlx-netns-helper.py"), "launch",
                       "--isolation", "rootless", "--proxy-port", "8080", "--profile", profile,
                       *extra, "--", "/missing/chromium", "--headless=new", "--remote-debugging-port=0",
                       "--user-data-dir=" + profile, "--proxy-server=http://127.0.0.1:8080"]
            return subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE, timeout=10, start_new_session=True)

    def test_rootless_launch_reports_actionable_errors_without_echoing_arguments(self):
        result = self.run_launch("--uid", "0", "--gid", "1")
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, b"")
        self.assertEqual(result.stderr,
                         b"namespace helper rejected preflight: ValueError: non-root browser identity required\n")
        result = self.run_launch("--uid", "65535", "--gid", "1")
        self.assertIn(b"non-root browser identity required", result.stderr)
        # Valid identity, but the proxy authority is absent: reported as an OS error, no argv echo.
        result = self.run_launch("--uid", "1", "--gid", "1")
        self.assertEqual(result.returncode, 1)
        self.assertNotIn(b"/missing/chromium", result.stderr)
        if os.geteuid() == 0:
            self.assertIn(b"refuses a root worker", result.stderr)
        else:
            self.assertIn(b"ConnectionRefusedError", result.stderr)

    def test_launch_requires_an_explicit_isolation_mode(self):
        result = subprocess.run([HELPER.PYTHON, "-I", str(HERE / "crawlx-netns-helper.py"), "launch",
                                 "--uid", "1", "--gid", "1", "--proxy-port", "8080",
                                 "--profile", "/tmp", "--", "/missing"],
                                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=5)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"--isolation", result.stderr)


class RealFixture:
    """Proxy-only fixture plus a bypass listener that must never be reached."""

    def start(self):
        self.reached = threading.Event()
        self.hits = []
        fixture = self

        class Proxy(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                fixture.hits.append(self.path)
                if self.path == "http://fixture.invalid/":
                    fixture.reached.set()
                body = b"<!doctype html><title>owned namespace fixture</title>"
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(body)

            def do_CONNECT(self):
                fixture.hits.append("CONNECT " + self.path)
                self.send_error(403)

            def log_message(self, *_args):
                return

        self.proxy = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Proxy)
        self.thread = threading.Thread(target=self.proxy.serve_forever, daemon=True)
        self.thread.start()
        # Host loopback services a namespaced browser must not reach directly.
        self.bypass = socket.socket()
        self.bypass.bind(("127.0.0.1", 0))
        self.bypass.listen()
        self.bypass.settimeout(0.05)
        self.bypass_connections = 0
        self.watch = threading.Event()
        self.bypass_thread = threading.Thread(target=self.watch_bypass, daemon=True)
        self.bypass_thread.start()
        return self

    def watch_bypass(self):
        while not self.watch.is_set():
            try:
                connection, _ = self.bypass.accept()
            except OSError:
                continue
            self.bypass_connections += 1
            connection.close()

    @property
    def port(self):
        return self.proxy.server_port

    def stop(self):
        self.watch.set()
        self.bypass_thread.join(timeout=5)
        self.bypass.close()
        self.proxy.shutdown()
        self.proxy.server_close()
        self.thread.join(timeout=5)


def group_members(group):
    """Live processes of a process group, from /proc."""
    members = []
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            stat = (entry / "stat").read_text()
        except OSError:
            continue
        fields = stat.rsplit(") ", 1)[1].split()
        if int(fields[2]) == group and fields[0] != "Z":
            members.append(int(entry.name))
    return members


def spawn_helper(command, profile):
    """Start the helper like the Rust launcher: own group, cleared environment, bounded stderr log."""
    environment = {"HOME": profile, "TMPDIR": profile, "XDG_CONFIG_HOME": profile + "/config",
                   "XDG_CACHE_HOME": profile + "/cache", "LANG": "en_US.UTF-8", "PATH": "/usr/bin:/bin"}
    log = tempfile.TemporaryFile()
    process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=log,
                               start_new_session=True, env=environment)
    process.log = log
    return process


def helper_stderr(process):
    process.log.seek(0)
    return process.log.read(8192).decode(errors="replace")


def finish_helper(process):
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.wait(timeout=5)
    for pipe in (process.stdin, process.stdout, process.log):
        pipe.close()


def wait_cdp(port):
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=1)
        try:
            connection.request("GET", "/json/version")
            response = connection.getresponse()
            if response.status == 200:
                return json.loads(response.read())
        except (OSError, http.client.HTTPException):
            time.sleep(0.05)
        finally:
            connection.close()
    return None


# Probe run inside the browser's namespace: sockets are real, nothing is mocked.
PROBE = '''import os, socket, subprocess, sys
role, dns_port = sys.argv[1], int(sys.argv[2])
status = open("/proc/self/status").read()
held = [line.split()[1].strip("0") for line in status.splitlines() if line.startswith(("CapEff", "CapPrm"))]
if role == "unprivileged":
    if os.getuid() == 0 or os.geteuid() == 0 or any(held):
        raise SystemExit("probe is not an unprivileged capability-free browser identity")
    # Without capabilities the browser identity cannot edit policy, routes or links.
    for argv in (["/usr/sbin/nft", "flush", "ruleset"],
                 ["/usr/sbin/ip", "link", "add", "crawlx0", "type", "dummy"],
                 ["/usr/sbin/ip", "route", "add", "default", "dev", "lo"]):
        if subprocess.run(argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
            raise SystemExit("browser identity changed network policy: " + argv[0])
elif role == "capable":
    # Capabilities are present, so only the nft policy can be denying below.
    if not any(held):
        raise SystemExit("capable probe lacks namespace capabilities")
else:
    raise SystemExit("unknown probe role")
def udp_roundtrip(port, label):
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind(("127.0.0.1", port))
    server.settimeout(0.3)
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # The nft output chain drops locally generated packets, which surfaces as EPERM.
        client.sendto(b"crawlx-owned-" + label, ("127.0.0.1", port))
        server.recvfrom(64)
    except (socket.timeout, PermissionError):
        return
    raise SystemExit("UDP datagram unexpectedly passed the firewall on " + str(port))
# Positive control: the one allowlisted loopback endpoint (the proxy) must accept.
socket.create_connection(("127.0.0.1", int(sys.argv[3])), 3).close()
udp_roundtrip(dns_port, b"udp")
listener = socket.socket()
listener.bind(("127.0.0.1", 0))
listener.listen()
client = socket.socket()
client.settimeout(0.3)
try:
    client.connect(listener.getsockname())
    raise SystemExit("direct loopback TCP unexpectedly passed firewall")
except (socket.timeout, OSError):
    pass
# The host's loopback services live in another network namespace and must not be reachable.
client = socket.socket()
client.settimeout(0.3)
try:
    client.connect(("127.0.0.1", int(sys.argv[4])))
    raise SystemExit("host loopback listener unexpectedly reachable from the namespace")
except (socket.timeout, OSError):
    pass
for address in (("192.0.2.1", 443), ("192.0.2.1", 53), ("2001:db8::1", 443), ("198.51.100.7", 80)):
    family = socket.AF_INET6 if ":" in address[0] else socket.AF_INET
    client = socket.socket(family)
    client.settimeout(0.3)
    try:
        client.connect(address)
        raise SystemExit("direct external route unexpectedly available: " + address[0])
    except OSError:
        pass
resolver = [line.split()[1] for line in open("/etc/resolv.conf") if line.startswith("nameserver")][:3]
for server in resolver or ["127.0.0.53"]:
    family = socket.AF_INET6 if ":" in server else socket.AF_INET
    client = socket.socket(family, socket.SOCK_DGRAM)
    client.settimeout(0.3)
    try:
        client.connect((server, 53))
        client.send(b"\\x12\\x34\\x01\\x00\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x00\\x07example\\x03com\\x00\\x00\\x01\\x00\\x01")
        client.recv(512)
        raise SystemExit("DNS answer received from " + server)
    except OSError:
        pass
'''

UNPRIVILEGED = ["--clear-groups", "--bounding-set=-all", "--inh-caps=-all", "--ambient-caps=-all", "--no-new-privs"]


@unittest.skipUnless(os.environ.get("CRAWLX_RUN_NETNS_ROOTLESS_ACCEPTANCE") == "1",
                     "rootless proof not selected")
class RootlessAcceptance(unittest.TestCase):
    def test_actual_chromium_proxy_cdp_network_denial_identity_and_group_cleanup(self):
        self.assertNotEqual(os.geteuid(), 0, "rootless proof must run as an ordinary user")
        chromium = os.environ["CRAWLX_CHROMIUM_PATH"]
        uid = int(os.environ.get("CRAWLX_NETNS_BROWSER_UID", "1000"))
        gid = int(os.environ.get("CRAWLX_NETNS_BROWSER_GID", "1000"))
        self.assertTrue(os.path.isabs(chromium))
        fixture = RealFixture().start()
        process = None
        try:
            with tempfile.TemporaryDirectory(prefix="crawlx-rootless-proof-") as profile:
                command = [HELPER.PYTHON, "-I", str(HERE / "crawlx-netns-helper.py"), "launch",
                           "--isolation", "rootless", "--uid", str(uid), "--gid", str(gid),
                           "--proxy-port", str(fixture.port), "--profile", profile, "--",
                           chromium, "--headless=new", "--remote-debugging-port=0",
                           "--user-data-dir=" + profile,
                           f"--proxy-server=http://127.0.0.1:{fixture.port}",
                           "--proxy-bypass-list=<-loopback>", "--no-first-run",
                           "--disable-background-networking", "http://fixture.invalid/"]
                process = spawn_helper(command, profile)
                ready, _, _ = select.select([process.stdout], [], [], 25)
                self.assertTrue(ready, "namespace evidence deadline exceeded")
                line = process.stdout.readline(HELPER.LIMIT + 1)
                if not line:
                    process.wait(timeout=5)
                    self.fail("rootless preflight failed: " + helper_stderr(process))
                evidence = json.loads(line)
                pid = evidence["browser_pid"]
                self.assertEqual(evidence["isolation"], "rootless")
                self.assertEqual(evidence["version"], HELPER.VERSION)
                # Distinct network and user namespaces, observed independently of the helper.
                self.assertNotEqual(evidence["namespace_inode"], os.stat("/proc/self/ns/net").st_ino)
                self.assertEqual(evidence["namespace_inode"], os.stat(f"/proc/{pid}/ns/net").st_ino)
                self.assertNotEqual(evidence["user_namespace_inode"], os.stat("/proc/self/ns/user").st_ino)
                self.assertEqual(evidence["user_namespace_inode"], os.stat(f"/proc/{pid}/ns/user").st_ino)
                # Actual kernel identity: subordinate uid/gid, never the worker, no groups/caps.
                self.assertNotEqual(evidence["host_uid"], os.geteuid())
                self.assertNotEqual(evidence["host_gid"], os.getegid())
                status = Path(f"/proc/{pid}/status").read_text()
                values = {key: value.split() for key, value in
                          (line.split(":", 1) for line in status.splitlines() if ":" in line)}
                self.assertEqual(values["Uid"], [str(evidence["host_uid"])] * 4)
                self.assertEqual(values["Gid"], [str(evidence["host_gid"])] * 4)
                self.assertEqual(values["Groups"], [])
                self.assertEqual(values["NoNewPrivs"], ["1"])
                for key in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"):
                    self.assertEqual(int(values[key][0], 16), 0, key)
                self.assertEqual(evidence["firewall"], HELPER.firewall_snapshot(fixture.port, evidence["cdp_port"]))
                self.assertEqual(evidence["interfaces"], ["lo"])
                process.stdin.write(b"RELEASE\n")
                process.stdin.flush()
                self.assertTrue(fixture.reached.wait(25), "Chromium did not use the existing proxy")
                version = wait_cdp(evidence["host_cdp_port"])
                self.assertIn("webSocketDebuggerUrl", version or {}, "CDP relay unreachable")
                # The release exec'd the configured Chromium inode (exposed read-only in the tmpfs).
                self.assertEqual(os.stat(f"/proc/{pid}/exe").st_ino, os.stat(chromium).st_ino)
                self.assertEqual(os.stat(f"/proc/{pid}/exe").st_dev, os.stat(chromium).st_dev)
                # Chromium's own sandbox must be live: a renderer under seccomp-bpf in this group.
                sandboxed = False
                deadline = time.monotonic() + 10
                while not sandboxed and time.monotonic() < deadline:
                    for member in group_members(process.pid):
                        try:
                            cmdline = Path(f"/proc/{member}/cmdline").read_bytes()
                            seccomp = [line for line in Path(f"/proc/{member}/status").read_text().splitlines()
                                       if line.startswith("Seccomp:")]
                        except OSError:
                            continue
                        if b"--type=renderer" in cmdline and seccomp and seccomp[0].split()[1] == "2":
                            sandboxed = True
                    time.sleep(0.1)
                self.assertTrue(sandboxed, "no seccomp-sandboxed Chromium renderer observed")
                # Chromium state must live in the bounded tmpfs, not on the host profile.
                self.assertEqual([entry.name for entry in Path(profile).iterdir() if not entry.name.startswith(".crawlx-netns-")], [])
                # Probe from inside the namespace as the actual browser identity (no caps),
                # then holding namespace capabilities so only nft can be denying DNS/direct paths.
                unprivileged = ["/usr/bin/setpriv", "--reuid", str(evidence["uid"]),
                                "--regid", str(evidence["gid"]), *UNPRIVILEGED]
                for prefix, role, dns_port in ((unprivileged, "unprivileged", 5353), ([], "capable", 53)):
                    result = subprocess.run(
                        [NSENTER, "--target", str(pid), "--user", "--net", "--", *prefix,
                         HELPER.PYTHON, "-I", "-c", PROBE, role, str(dns_port), str(fixture.port),
                         str(fixture.bypass.getsockname()[1])],
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
                    self.assertEqual(result.returncode, 0, role + ": " + result.stderr.decode(errors="replace"))
                self.assertEqual(fixture.bypass_connections, 0, "browser namespace reached a host loopback listener")
                self.assertIn("http://fixture.invalid/", fixture.hits)
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=5)
                deadline = time.monotonic() + 5
                while group_members(process.pid) and time.monotonic() < deadline:
                    time.sleep(0.02)
                self.assertEqual(group_members(process.pid), [], "namespace process survived group cleanup")
                self.assertFalse(Path(f"/proc/{pid}/ns/net").exists())
        finally:
            if process is not None:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait(timeout=5)
                finish_helper(process)
            fixture.stop()


@unittest.skipUnless(os.environ.get("CRAWLX_RUN_NETNS_ACCEPTANCE") == "1", "privileged proof not selected")
class PrivilegedAcceptance(unittest.TestCase):
    def test_actual_chromium_proxy_cdp_network_denial_and_group_cleanup(self):
        self.assertEqual(os.geteuid(), 0, "root worker authority is required")
        chromium = os.environ["CRAWLX_CHROMIUM_PATH"]
        uid = int(os.environ["CRAWLX_NETNS_BROWSER_UID"])
        gid = int(os.environ["CRAWLX_NETNS_BROWSER_GID"])
        self.assertGreater(uid, 0)
        self.assertGreater(gid, 0)
        self.assertTrue(os.path.isabs(chromium))
        fixture = RealFixture().start()
        process = None
        try:
            with tempfile.TemporaryDirectory(prefix="crawlx-netns-proof-") as profile:
                command = [HELPER.PYTHON, "-I", str(HERE / "crawlx-netns-helper.py"), "launch",
                           "--isolation", "privileged", "--uid", str(uid), "--gid", str(gid),
                           "--proxy-port", str(fixture.port), "--profile", profile, "--",
                           chromium, "--headless=new", "--remote-debugging-port=0",
                           "--user-data-dir=" + profile,
                           f"--proxy-server=http://127.0.0.1:{fixture.port}",
                           "--proxy-bypass-list=<-loopback>", "--no-first-run",
                           "--disable-background-networking", "http://fixture.invalid/"]
                process = spawn_helper(command, profile)
                ready, _, _ = select.select([process.stdout], [], [], 25)
                self.assertTrue(ready, "namespace evidence deadline exceeded")
                line = process.stdout.readline(HELPER.LIMIT + 1)
                if not line:
                    process.wait(timeout=5)
                    self.fail("namespace preflight failed: " + helper_stderr(process))
                evidence = json.loads(line)
                pid = evidence["browser_pid"]
                self.assertEqual(evidence["isolation"], "privileged")
                self.assertEqual(evidence["host_uid"], uid)
                self.assertEqual(evidence["user_namespace_inode"], os.stat("/proc/self/ns/user").st_ino)
                self.assertNotEqual(evidence["namespace_inode"], os.stat("/proc/self/ns/net").st_ino)
                self.assertEqual(evidence["namespace_inode"], os.stat(f"/proc/{pid}/ns/net").st_ino)
                self.assertEqual(evidence["firewall"], HELPER.firewall_snapshot(fixture.port, evidence["cdp_port"]))
                process.stdin.write(b"RELEASE\n")
                process.stdin.flush()
                self.assertTrue(fixture.reached.wait(25), "Chromium did not use the existing proxy")
                version = wait_cdp(evidence["host_cdp_port"])
                self.assertIn("webSocketDebuggerUrl", version or {})
                result = subprocess.run(
                    [NSENTER, "--target", str(pid), "--net", "--", HELPER.PYTHON, "-I", "-c", PROBE,
                     "capable", "53", str(fixture.port), str(fixture.bypass.getsockname()[1])],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
                self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
                self.assertEqual(fixture.bypass_connections, 0)
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=5)
                deadline = time.monotonic() + 5
                while Path(f"/proc/{pid}/ns/net").exists() and time.monotonic() < deadline:
                    time.sleep(0.02)
                self.assertFalse(Path(f"/proc/{pid}/ns/net").exists(), "namespace process survived group cleanup")
        finally:
            if process is not None:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait(timeout=5)
                finish_helper(process)
            fixture.stop()


if __name__ == "__main__":
    unittest.main()
