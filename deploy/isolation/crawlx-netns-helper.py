#!/usr/bin/python3 -I
"""Anonymous network namespace launcher, protocol version 2.

Two isolation modes, selected by the operator with ``--isolation``:

``privileged``
    Install root:root, mode 0755, below root-owned non-writable directories.
    The worker must be root; ``unshare --net`` creates the namespace and the
    nft policy is installed by host root. Chromium runs as the configured
    non-root host identity.

``rootless``
    The worker runs as an ordinary non-root user. ``unshare --user
    --map-root-user --map-users=auto --map-groups=auto --net`` creates a user
    namespace whose root is the worker's own host identity and whose other
    identities are the user's /etc/subuid and /etc/subgid ranges (applied by
    the setuid-less file-capability tools newuidmap/newgidmap). Namespace root
    configures loopback and the nft policy, then Chromium is started in a
    private mount namespace under a distinct subordinate identity with no
    capabilities and no-new-privileges. Chromium state lives in a size-bounded
    tmpfs over the profile directory that disappears with the namespace, and
    the Chromium install directory is exposed read-only inside that tmpfs so
    the subordinate identity can execute it. Chromium's own sandbox is retained.

Requires /usr/bin/unshare, /usr/bin/setpriv, /usr/sbin/ip, /usr/sbin/nft
(rootless additionally /usr/bin/mount, /usr/bin/newuidmap, /usr/bin/newgidmap).
No shell is evaluated. A single bounded JSON evidence line precedes RELEASE on
stdin. EOF aborts. All descendants retain the worker-owned process group.
Anonymous namespace lifetime ends when that group dies; no named namespace or
host firewall remains. This is network isolation, not protection against
kernel attacks and not a filesystem sandbox beyond the rootless profile tmpfs.
"""

import argparse
import asyncio
import json
import os
import signal
import socket
import subprocess
import sys
import tempfile
from pathlib import Path

IP = "/usr/sbin/ip"
NFT = "/usr/sbin/nft"
PYTHON = "/usr/bin/python3"
UNSHARE = "/usr/bin/unshare"
SETPRIV = "/usr/bin/setpriv"
MOUNT = "/usr/bin/mount"
NEWUIDMAP = "/usr/bin/newuidmap"
NEWGIDMAP = "/usr/bin/newgidmap"
LIMIT = 65536
CONNECTION_LIMIT = 128
VERSION = 2
ISOLATIONS = ("privileged", "rootless")
# Rootless Chromium identities must lie in the subordinate range applied by
# --map-users=auto: namespace ids 1..65535 (65535 itself is excluded as -1).
ROOTLESS_MAX_ID = 65534
PROFILE_TMPFS = "size=512m,nr_inodes=131072,mode=0700,nosuid,nodev"
BROWSER_EXPOSURE = ".crawlx-browser"


def run(argv, data=None):
    """Run a fixed executable and argv without shell expansion."""
    return subprocess.run(argv, input=data, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, check=True, timeout=10).stdout


def read_json(argv):
    return json.loads(run(argv))


def emit(value):
    payload = json.dumps(value, separators=(",", ":"), sort_keys=True).encode() + b"\n"
    if len(payload) > LIMIT:
        raise ValueError("oversized namespace evidence")
    sys.stdout.buffer.write(payload)
    sys.stdout.buffer.flush()


def firewall_snapshot(proxy, cdp):
    """Exact canonical policy also checked by the Rust verifier."""
    ports = sorted((proxy, cdp))
    objects = [{"table": {"family": "inet", "name": "crawlx"}}]
    for chain in ("input", "output", "forward"):
        objects.append({"chain": {"family": "inet", "table": "crawlx", "name": chain,
                                  "type": "filter", "hook": chain, "prio": 0, "policy": "drop"}})
    for chain in ("input", "output"):
        for direction in ("dport", "sport"):
            expr = [
                {"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "daddr"}},
                           "right": "127.0.0.1"}},
                {"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": direction}},
                           "right": {"set": ports}}},
            ]
            if direction == "sport":
                expr.append({"match": {"op": "==", "left": {"ct": {"key": "state"}},
                                       "right": "established"}})
            expr.append({"accept": None})
            objects.append({"rule": {"family": "inet", "table": "crawlx", "chain": chain, "expr": expr}})
    return objects


def canonical_firewall(raw):
    """Remove only kernel handles and nft metadata; reject every other extra object."""
    result = []
    for entry in raw["nftables"]:
        if set(entry) == {"metainfo"}:
            continue
        if len(entry) != 1:
            raise ValueError("invalid firewall object")
        kind, value = next(iter(entry.items()))
        if kind not in ("table", "chain", "rule"):
            raise ValueError("unexpected firewall object")
        value = dict(value)
        value.pop("handle", None)
        result.append({kind: value})
    return result


def topology():
    links = read_json([IP, "-j", "link", "show"])
    interfaces = sorted(link["ifname"] for link in links)
    if interfaces != ["lo"]:
        raise ValueError("non-loopback interface present")
    routes = []
    for family in (4, 6):
        for route in read_json([IP, f"-{family}", "-j", "route", "show", "table", "all"]):
            item = {"family": family, "dst": route.get("dst", "default"),
                    "kind": route.get("type", "unicast"), "dev": route.get("dev", "")}
            allowed = ("127.0.0.0/8", "127.0.0.1", "127.255.255.255") if family == 4 else ("::1",)
            if item["dst"] not in allowed or item["kind"] not in ("local", "broadcast") or item["dev"] != "lo":
                raise ValueError("non-loopback route present")
            routes.append(item)
    if not routes:
        raise ValueError("missing loopback routes")
    return interfaces, routes


def validate_args(args):
    maximum = ROOTLESS_MAX_ID if args.isolation == "rootless" else 4294967294
    if not 0 < args.uid <= maximum or not 0 < args.gid <= maximum:
        raise ValueError("non-root browser identity required")
    if args.proxy_port <= 0 or args.proxy_port > 65535 or args.proxy_port == 53:
        raise ValueError("invalid proxy endpoint")
    if not args.command or not os.path.isabs(args.command[0]):
        raise ValueError("absolute Chromium executable required")
    profile = Path(args.profile)
    if not profile.is_absolute() or profile.is_symlink() or not profile.is_dir():
        raise ValueError("fresh absolute profile directory required")
    expected_profile = "--user-data-dir=" + str(profile)
    if args.command.count("--remote-debugging-port=0") != 1 or args.command.count(expected_profile) != 1:
        raise ValueError("managed debugging and profile flags required")
    if "--headless=new" not in args.command or "--no-sandbox" in args.command:
        raise ValueError("headless sandboxed Chromium required")
    if args.command.count(f"--proxy-server=http://127.0.0.1:{args.proxy_port}") != 1:
        raise ValueError("existing loopback proxy authority required")


def read_id_map(path):
    """Parse a kernel uid_map/gid_map into (inside, outside, count) tuples."""
    entries = []
    for line in Path(path).read_text().splitlines():
        inside, outside, count = (int(part) for part in line.split())
        entries.append((inside, outside, count))
    return entries


def map_id(entries, inside):
    for first, outside, count in entries:
        if first <= inside < first + count:
            return outside + (inside - first)
    return None


def rootless_identity(uid_map, gid_map, owner_uid, owner_gid, uid, gid):
    """Host identity of a namespace browser id, rejecting any aliasing of the worker.

    Namespace root must be exactly the worker (the namespace owner). The browser
    id must map through a different range and no other range may reach the
    worker's host uid/gid, so Chromium never shares a kernel identity with the
    worker, its credentials, files, or ptrace/signal authority.
    """
    result = []
    for entries, owner, ns_id in ((uid_map, owner_uid, uid), (gid_map, owner_gid, gid)):
        if not entries or entries[0] != (0, owner, 1):
            raise ValueError("namespace root is not the worker identity")
        if ns_id == 0:
            raise ValueError("non-root browser identity required")
        host = map_id(entries, ns_id)
        if host is None or host == owner:
            raise ValueError("browser identity is unmapped or aliases the worker")
        for _inside, outside, count in entries[1:]:
            if outside <= owner < outside + count:
                raise ValueError("subordinate range includes the worker identity")
        result.append(host)
    return tuple(result)


def status_value(pid, key):
    for line in Path(f"/proc/{pid}/status").read_text().splitlines():
        if line.startswith(key):
            return line[len(key):].split()
    raise ValueError("process status field missing")


def verify_gate_identity(pid, uid, gid):
    """Namespace-view proof of the gate: exact ids, no groups, no caps, no new privileges."""
    if status_value(pid, "Uid:") != [str(uid)] * 4 or status_value(pid, "Gid:") != [str(gid)] * 4:
        raise ValueError("gate identity differs from configured browser identity")
    if status_value(pid, "Groups:"):
        raise ValueError("gate retained supplementary groups")
    for key in ("CapInh:", "CapPrm:", "CapEff:", "CapBnd:", "CapAmb:"):
        if int(status_value(pid, key)[0], 16) != 0:
            raise ValueError("gate retained capabilities")
    if status_value(pid, "NoNewPrivs:") != ["1"]:
        raise ValueError("gate lacks no-new-privileges")


async def bridge(reader, writer):
    try:
        while data := await reader.read(65536):
            writer.write(data)
            await writer.drain()
    finally:
        writer.close()
        await writer.wait_closed()


class Relays:
    """Bound concurrent TCP streams without buffering complete responses."""
    def __init__(self):
        self.active = set()
        self.tasks = set()
        self.servers = []

    async def accept(self, reader, writer, connect):
        if len(self.active) >= CONNECTION_LIMIT:
            writer.close()
            await writer.wait_closed()
            return
        self.active.add(writer)
        try:
            peer_reader, peer_writer = await asyncio.wait_for(connect(), 5)
            async with asyncio.TaskGroup() as group:
                group.create_task(bridge(reader, peer_writer))
                group.create_task(bridge(peer_reader, writer))
        except (OSError, TimeoutError, ExceptionGroup):
            writer.close()
        finally:
            self.active.discard(writer)
            await writer.wait_closed()

    def handler(self, connect):
        def schedule(reader, writer):
            task = asyncio.create_task(self.accept(reader, writer, connect))
            self.tasks.add(task)
            task.add_done_callback(self.tasks.discard)
        return schedule

    async def close(self):
        for server in self.servers:
            server.close()
            await server.wait_closed()
        for task in self.tasks:
            task.cancel()
        await asyncio.gather(*self.tasks, return_exceptions=True)


async def bounded_line(stream):
    return await asyncio.wait_for(stream.readline(), 20)


async def stdin_line():
    reader = asyncio.StreamReader(limit=LIMIT)
    protocol = asyncio.StreamReaderProtocol(reader)
    await asyncio.get_running_loop().connect_read_pipe(lambda: protocol, sys.stdin.buffer)
    return await bounded_line(reader)


def gate():
    """Capability-cleared process reports readiness, waits, then execs Chromium."""
    if os.getuid() == 0 or os.getgid() == 0:
        raise ValueError("root browser gate refused")
    sys.stdout.write("GATE\n")
    sys.stdout.flush()
    if sys.stdin.buffer.readline(16) != b"RELEASE\n":
        raise ValueError("gate release missing")
    command = sys.argv[2:]
    os.execv(command[0], command)


def setpriv_gate(uid, gid, command):
    """Drop to the browser identity without groups, capabilities or new privileges."""
    return [SETPRIV, "--reuid", str(uid), "--regid", str(gid), "--clear-groups",
            "--bounding-set=-all", "--inh-caps=-all", "--ambient-caps=-all", "--no-new-privs",
            "--pdeathsig", "SIGKILL", PYTHON, "-I", str(Path(__file__).resolve()), "gate", *command]


def confine():
    """Rootless mount stage, run as namespace root in a private mount namespace.

    Chromium state moves onto a bounded tmpfs over the profile directory, so the
    subordinate identity never writes host files and nothing outlives the
    namespace. The Chromium install directory is bind-mounted read-only inside
    that tmpfs because the subordinate identity generally cannot traverse the
    operator's home. The same process then execs the capability-cleared gate.
    """
    if len(sys.argv) < 7 or sys.argv[5] != "--":
        raise ValueError("invalid confine arguments")
    uid, gid, profile, command = int(sys.argv[2]), int(sys.argv[3]), sys.argv[4], sys.argv[6:]
    if os.geteuid() != 0 or not 0 < uid <= ROOTLESS_MAX_ID or not 0 < gid <= ROOTLESS_MAX_ID:
        raise ValueError("rootless confine requires namespace root and a subordinate identity")
    executable = os.path.realpath(command[0])
    install = os.path.dirname(executable)
    if install == "/" or not os.path.isfile(executable):
        raise ValueError("Chromium executable must live in its own directory")
    run([MOUNT, "-t", "tmpfs", "-o", f"{PROFILE_TMPFS},uid={uid},gid={gid}", "tmpfs", profile])
    exposure = os.path.join(profile, BROWSER_EXPOSURE)
    os.mkdir(exposure, 0o755)
    run([MOUNT, "--bind", install, exposure])
    run([MOUNT, "-o", "remount,bind,ro", exposure])
    command[0] = os.path.join(exposure, os.path.basename(executable))
    os.execv(SETPRIV, setpriv_gate(uid, gid, command))


async def inner(args):
    """Configure and attest inside anonymous namespace, before browser exec."""
    validate_args(args)
    rootless = args.isolation == "rootless"
    host_net = int(os.environ["CRAWLX_HOST_NET_INODE"])
    host_user = int(os.environ["CRAWLX_HOST_USER_INODE"])
    inode = os.stat("/proc/self/ns/net").st_ino
    user_inode = os.stat("/proc/self/ns/user").st_ino
    if inode == host_net:
        raise ValueError("unshare did not create distinct namespace")
    if (user_inode != host_user) != rootless:
        raise ValueError("user namespace does not match isolation mode")
    host_uid, host_gid = args.uid, args.gid
    if rootless:
        if os.geteuid() != 0 or os.getegid() != 0:
            raise ValueError("namespace root identity missing")
        owner_uid, owner_gid = int(os.environ["CRAWLX_OWNER_UID"]), int(os.environ["CRAWLX_OWNER_GID"])
        # Inside the owning namespace, /proc maps ids to the parent (host) view.
        host_uid, host_gid = rootless_identity(
            read_id_map("/proc/self/uid_map"), read_id_map("/proc/self/gid_map"),
            owner_uid, owner_gid, args.uid, args.gid)
    run([IP, "link", "set", "lo", "up"])
    reserved = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    reserved.bind(("127.0.0.1", 0))
    cdp = reserved.getsockname()[1]
    if cdp in (53, args.proxy_port):
        raise ValueError("CDP port collided with proxy/DNS")
    expected = firewall_snapshot(args.proxy_port, cdp)
    commands = [{"add": item} for item in expected]
    run([NFT, "-j", "-f", "-"], json.dumps({"nftables": commands}).encode())
    actual = canonical_firewall(read_json([NFT, "-j", "list", "ruleset"]))
    if actual != expected:
        raise ValueError("installed firewall differs from exact policy")
    interfaces, routes = topology()
    relays = Relays()
    proxy = await asyncio.start_server(relays.handler(lambda: asyncio.open_unix_connection(args.proxy_socket)),
                                       "127.0.0.1", args.proxy_port)
    cdp_server = await asyncio.start_unix_server(relays.handler(lambda: asyncio.open_connection("127.0.0.1", cdp)),
                                                args.cdp_socket)
    relays.servers.extend([proxy, cdp_server])
    command = [f"--remote-debugging-port={cdp}" if item == "--remote-debugging-port=0" else item
               for item in args.command]
    if rootless:
        launcher = [UNSHARE, "--mount", "--propagation", "private", "--", PYTHON, "-I",
                    str(Path(__file__).resolve()), "confine", str(args.uid), str(args.gid),
                    args.profile, "--", *command]
    else:
        launcher = setpriv_gate(args.uid, args.gid, command)
    browser = await asyncio.create_subprocess_exec(
        *launcher, stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
        stderr=None, limit=LIMIT)
    try:
        if await bounded_line(browser.stdout) != b"GATE\n":
            raise ValueError("unprivileged browser gate failed")
        if os.stat(f"/proc/{browser.pid}/ns/net").st_ino != inode:
            raise ValueError("gate escaped namespace")
        if os.stat(f"/proc/{browser.pid}/ns/user").st_ino != user_inode:
            raise ValueError("gate escaped user namespace")
        verify_gate_identity(browser.pid, args.uid, args.gid)
        emit({"version": VERSION, "isolation": args.isolation, "browser_pid": browser.pid,
              "namespace_inode": inode, "user_namespace_inode": user_inode,
              "proxy_port": args.proxy_port, "cdp_port": cdp,
              "host_cdp_port": args.host_cdp_port, "uid": args.uid, "gid": args.gid,
              "host_uid": host_uid, "host_gid": host_gid,
              "interfaces": interfaces, "routes": routes, "firewall": actual})
        if await stdin_line() != b"RELEASE\n":
            raise ValueError("namespace release missing")
        # Recheck enforcement immediately before network-capable Chromium exec.
        if topology() != (interfaces, routes) or canonical_firewall(read_json([NFT, "-j", "list", "ruleset"])) != expected:
            raise ValueError("namespace policy changed before exec")
        reserved.close()
        browser.stdin.write(b"RELEASE\n")
        await browser.stdin.drain()
        browser.stdin.close()
        # Chromium stdout is not part of the evidence protocol; drain it boundedly.
        while await browser.stdout.read(65536):
            pass
        return await browser.wait()
    finally:
        reserved.close()
        if browser.returncode is None:
            browser.kill()
            await browser.wait()
        await relays.close()


def preflight_host(args):
    """Host-side prerequisites for the selected isolation mode."""
    rootless = args.isolation == "rootless"
    if rootless:
        if os.geteuid() == 0:
            raise ValueError("rootless namespace mode refuses a root worker; use privileged mode")
        required = (IP, NFT, PYTHON, UNSHARE, SETPRIV, MOUNT, NEWUIDMAP, NEWGIDMAP)
        try:
            if int(Path("/proc/sys/user/max_user_namespaces").read_text()) <= 0:
                raise ValueError("user namespaces are disabled")
        except OSError as error:
            raise ValueError("user namespace support unavailable") from error
    else:
        if os.geteuid() != 0:
            raise ValueError("namespace helper requires root")
        required = (IP, NFT, PYTHON, UNSHARE, SETPRIV)
    for executable in required:
        if not os.path.isfile(executable) or not os.access(executable, os.X_OK):
            raise ValueError("required isolation executable unavailable: " + executable)


def unshare_command(args):
    if args.isolation == "rootless":
        return [UNSHARE, "--user", "--map-root-user", "--map-users=auto", "--map-groups=auto", "--net", "--"]
    return [UNSHARE, "--net", "--"]


async def outer(args):
    """Host relays preserve the existing proxy authority and loopback CDP client."""
    validate_args(args)
    preflight_host(args)
    rootless = args.isolation == "rootless"
    # Confirm the authority exists without sending an HTTP request or bypassing it.
    with socket.create_connection(("127.0.0.1", args.proxy_port), timeout=3):
        pass
    if not rootless:
        os.chown(args.profile, args.uid, args.gid)
    relays = Relays()
    with tempfile.TemporaryDirectory(prefix=".crawlx-netns-", dir=args.profile) as directory:
        proxy_path = os.path.join(directory, "proxy.sock")
        cdp_path = os.path.join(directory, "cdp.sock")
        proxy = await asyncio.start_unix_server(
            relays.handler(lambda: asyncio.open_connection("127.0.0.1", args.proxy_port)), proxy_path)
        host_cdp = await asyncio.start_server(
            relays.handler(lambda: asyncio.open_unix_connection(cdp_path)), "127.0.0.1", 0)
        relays.servers.extend([proxy, host_cdp])
        host_port = host_cdp.sockets[0].getsockname()[1]
        environment = dict(os.environ)
        environment["CRAWLX_HOST_NET_INODE"] = str(os.stat("/proc/self/ns/net").st_ino)
        environment["CRAWLX_HOST_USER_INODE"] = str(os.stat("/proc/self/ns/user").st_ino)
        environment["CRAWLX_OWNER_UID"] = str(os.geteuid())
        environment["CRAWLX_OWNER_GID"] = str(os.getegid())
        if rootless:
            # unshare locates newuidmap/newgidmap through PATH; never trust the caller's.
            environment["PATH"] = "/usr/bin:/usr/sbin"
        child = await asyncio.create_subprocess_exec(
            *unshare_command(args), PYTHON, "-I", str(Path(__file__).resolve()), "inner",
            "--isolation", args.isolation,
            "--uid", str(args.uid), "--gid", str(args.gid), "--proxy-port", str(args.proxy_port),
            "--profile", args.profile, "--proxy-socket", proxy_path, "--cdp-socket", cdp_path,
            "--host-cdp-port", str(host_port), "--", *args.command,
            stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, stderr=None,
            env=environment, limit=LIMIT)
        try:
            line = await bounded_line(child.stdout)
            if len(line) > LIMIT or not line.endswith(b"\n"):
                raise ValueError("namespace preflight produced no bounded evidence")
            evidence = json.loads(line)
            if evidence["host_cdp_port"] != host_port or evidence["isolation"] != args.isolation:
                raise ValueError("CDP relay or isolation evidence mismatch")
            browser = evidence["browser_pid"]
            user_inode = os.stat(f"/proc/{browser}/ns/user").st_ino
            if evidence["user_namespace_inode"] != user_inode:
                raise ValueError("user namespace evidence mismatch")
            if rootless:
                # Independent host-view proof: distinct namespace, worker-owned root,
                # and a browser kernel identity that never aliases the worker.
                if user_inode == os.stat("/proc/self/ns/user").st_ino:
                    raise ValueError("rootless launch did not create a user namespace")
                identity = rootless_identity(
                    read_id_map(f"/proc/{browser}/uid_map"), read_id_map(f"/proc/{browser}/gid_map"),
                    os.geteuid(), os.getegid(), evidence["uid"], evidence["gid"])
                if identity != (evidence["host_uid"], evidence["host_gid"]):
                    raise ValueError("host identity evidence mismatch")
            emit(evidence)
            if await stdin_line() != b"RELEASE\n":
                raise ValueError("worker release missing")
            child.stdin.write(b"RELEASE\n")
            await child.stdin.drain()
            child.stdin.close()
            # EOF after the one evidence line confirms no unexpected protocol output.
            if await child.stdout.read(1):
                raise ValueError("unexpected helper protocol output")
            return await child.wait()
        finally:
            if child.returncode is None:
                child.kill()
                await child.wait()
            await relays.close()


async def supervise_outer(args):
    """Kill the entire owned group if the worker dies without running Drop."""
    owner = os.getppid()
    group = os.getpgrp()
    if owner <= 1 or group != os.getpid():
        raise ValueError("helper must lead a worker-owned process group")
    owner_fd = os.pidfd_open(owner)
    loop = asyncio.get_running_loop()
    try:
        if os.getppid() != owner:
            raise ValueError("worker disappeared during supervision setup")
        loop.add_reader(owner_fd, lambda: os.killpg(group, signal.SIGKILL))
        return await outer(args)
    finally:
        loop.remove_reader(owner_fd)
        os.close(owner_fd)


def arguments():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("launch", "inner"))
    parser.add_argument("--isolation", choices=ISOLATIONS, required=True)
    parser.add_argument("--uid", type=int, required=True)
    parser.add_argument("--gid", type=int, required=True)
    parser.add_argument("--proxy-port", type=int, required=True)
    parser.add_argument("--profile", required=True)
    parser.add_argument("--proxy-socket")
    parser.add_argument("--cdp-socket")
    parser.add_argument("--host-cdp-port", type=int)
    before, command = sys.argv[1:], []
    if "--" in before:
        split = before.index("--")
        before, command = before[:split], before[split + 1:]
    args = parser.parse_args(before)
    args.command = command
    return args


def describe(error):
    """Bounded, argv-free failure text for operators.

    Fixed isolation tools (ip, nft, unshare, mount, setpriv, newuidmap) never see
    browser argv, page URLs, proxy credentials or inherited secrets as arguments,
    so their short exit status and stderr are safe and actionable.
    """
    text = type(error).__name__
    if isinstance(error, subprocess.CalledProcessError):
        detail = (error.stderr or b"")[:240].decode(errors="replace").strip()
        text += f": {os.path.basename(str(error.cmd[0]))} exit {error.returncode}"
        if detail:
            text += ": " + detail
    elif isinstance(error, subprocess.TimeoutExpired):
        text += f": {os.path.basename(str(error.cmd[0]))} timed out"
    elif isinstance(error, ValueError) and error.args:
        # Helper-authored contract messages carry no caller data.
        text += ": " + str(error.args[0])
    return "namespace helper rejected preflight: " + text


if __name__ == "__main__":
    try:
        if len(sys.argv) > 1 and sys.argv[1] == "gate":
            gate()
        elif len(sys.argv) > 1 and sys.argv[1] == "confine":
            confine()
        else:
            parsed = arguments()
            sys.exit(asyncio.run(supervise_outer(parsed) if parsed.mode == "launch" else inner(parsed)))
    except (OSError, ValueError, KeyError, subprocess.SubprocessError, TimeoutError) as error:
        print(describe(error), file=sys.stderr)
        sys.exit(1)
