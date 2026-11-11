#!/usr/bin/env python3
"""Merge the pinned Chromium identity evidence into a scanner SBOM.

Reads a scanner-produced BOM (release CycloneDX JSON or image SPDX 2.x JSON),
validates docs/identity-profile-provenance.json against chromium-pin.toml, and
writes the BOM with one appended engine component/package (plus nested notice
and executable entries). Nothing the scanner produced is modified or removed;
the result is re-checked for that before it is written. Licenses are always
NOASSERTION: the measured evidence names no license and none is invented. The
distribution approval stays `external_required`; the output makes no claim of
wire equivalence with any other browser build.

Standard library only. Exit status 0 on success, 1 on any rejected input.
"""

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import tempfile
import tomllib

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_PIN = ROOT / "chromium-pin.toml"
DEFAULT_PROVENANCE = ROOT / "docs" / "identity-profile-provenance.json"

SCHEMA = "crawlx.identity-profile-provenance/1"
APPROVAL = "external_required"
NOASSERTION = "NOASSERTION"
ROLES = ("ca_or_transport_notice", "compression", "tls")
SHA256 = re.compile(r"[0-9a-f]{64}")
PROVENANCE_KEYS = {
    "schema",
    "engine",
    "version",
    "platform",
    "archiveSha256",
    "executableSha256",
    "embeddedNoticesSha256",
    "embeddedNoticesBytes",
    "embeddedNoticesCount",
    "roles",
    "distributionApproval",
}
ROLE_KEYS = {"role", "noticeSha256", "noticeBytes"}
PROP = "crawlx:identity:"


class IdentitySbomError(Exception):
    """Input, pin, evidence, or output rejected."""


def _reject_duplicate_keys(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise IdentitySbomError(f"duplicate JSON object key {key!r}")
        out[key] = value
    return out


def load_json(path):
    try:
        text = Path(path).read_text(encoding="utf-8")
        return json.loads(text, object_pairs_hook=_reject_duplicate_keys)
    except (OSError, UnicodeDecodeError) as err:
        raise IdentitySbomError(f"cannot read {path}: {err}") from err
    except json.JSONDecodeError as err:
        raise IdentitySbomError(f"{path} is not valid JSON: {err}") from err


def _is_sha256(value):
    return isinstance(value, str) and SHA256.fullmatch(value) is not None


def _is_positive_int(value):
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def load_pin(path):
    """Return (version, platform, archive_sha256, download_url) from the pin file."""
    try:
        with open(path, "rb") as handle:
            pin = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as err:
        raise IdentitySbomError(f"cannot read pin {path}: {err}") from err
    section = pin.get("chromium")
    if not isinstance(section, dict):
        raise IdentitySbomError("pin has no [chromium] table")
    fields = {}
    for key in ("version", "os", "arch", "download_url", "sha256"):
        value = section.get(key)
        if not isinstance(value, str) or not value:
            raise IdentitySbomError(f"pin [chromium].{key} missing or not a string")
        fields[key] = value
    if not _is_sha256(fields["sha256"]):
        raise IdentitySbomError("pin [chromium].sha256 is not 64 lowercase hex digits")
    if f"/{fields['version']}/" not in fields["download_url"]:
        raise IdentitySbomError("pin download_url does not contain the pinned version")
    platform = f"{fields['os']}-{fields['arch']}"
    return fields["version"], platform, fields["sha256"], fields["download_url"]


def validate_provenance(doc, pin):
    """Validate evidence syntax and bind it to the pin. Returns normalized evidence."""
    version, platform, archive_sha, download_url = pin
    if not isinstance(doc, dict):
        raise IdentitySbomError("provenance must be a JSON object")
    keys = set(doc)
    if keys != PROVENANCE_KEYS:
        extra = sorted(keys - PROVENANCE_KEYS)
        missing = sorted(PROVENANCE_KEYS - keys)
        raise IdentitySbomError(f"provenance keys mismatch: extra={extra} missing={missing}")
    if doc["schema"] != SCHEMA:
        raise IdentitySbomError(f"provenance schema must be {SCHEMA!r}")
    if doc["engine"] != "Chromium":
        raise IdentitySbomError("provenance engine must be 'Chromium'")
    if doc["version"] != version:
        raise IdentitySbomError(
            f"provenance version {doc['version']!r} does not match pin {version!r}"
        )
    if doc["platform"] != platform:
        raise IdentitySbomError(
            f"provenance platform {doc['platform']!r} does not match pin {platform!r}"
        )
    for key in ("archiveSha256", "executableSha256", "embeddedNoticesSha256"):
        if not _is_sha256(doc[key]):
            raise IdentitySbomError(f"provenance {key} is not 64 lowercase hex digits")
    if doc["archiveSha256"] != archive_sha:
        raise IdentitySbomError("provenance archiveSha256 does not match the pinned archive")
    for key in ("embeddedNoticesBytes", "embeddedNoticesCount"):
        if not _is_positive_int(doc[key]):
            raise IdentitySbomError(f"provenance {key} must be a positive integer")
    if doc["distributionApproval"] != APPROVAL:
        raise IdentitySbomError(f"provenance distributionApproval must be {APPROVAL!r}")

    roles = doc["roles"]
    if not isinstance(roles, list) or not roles:
        raise IdentitySbomError("provenance roles must be a non-empty list")
    seen = {}
    for entry in roles:
        if not isinstance(entry, dict) or set(entry) != ROLE_KEYS:
            raise IdentitySbomError(f"role entry must have exactly keys {sorted(ROLE_KEYS)}")
        if entry["role"] not in ROLES:
            raise IdentitySbomError(f"unknown notice role {entry['role']!r}")
        if not _is_sha256(entry["noticeSha256"]):
            raise IdentitySbomError("role noticeSha256 is not 64 lowercase hex digits")
        if not _is_positive_int(entry["noticeBytes"]):
            raise IdentitySbomError("role noticeBytes must be a positive integer")
        key = (entry["role"], entry["noticeSha256"])
        if key in seen:
            raise IdentitySbomError(
                f"duplicate notice receipt for role {key[0]!r} sha256 {key[1]}"
            )
        seen[key] = entry["noticeBytes"]
    for sha in {sha for _, sha in seen}:
        sizes = {size for (_, s), size in seen.items() if s == sha}
        if len(sizes) != 1:
            raise IdentitySbomError(f"notice {sha} has conflicting byte sizes across roles")
    if len(seen) > doc["embeddedNoticesCount"]:
        raise IdentitySbomError("more role notices than embeddedNoticesCount")
    if any(size > doc["embeddedNoticesBytes"] for size in seen.values()):
        raise IdentitySbomError("role notice larger than embeddedNoticesBytes")

    return {
        "version": version,
        "platform": platform,
        "download_url": download_url,
        "archive": doc["archiveSha256"],
        "executable": doc["executableSha256"],
        "notices_sha": doc["embeddedNoticesSha256"],
        "notices_bytes": doc["embeddedNoticesBytes"],
        "notices_count": doc["embeddedNoticesCount"],
        "roles": [
            {"role": role, "sha": sha, "bytes": size}
            for (role, sha), size in sorted(seen.items())
        ],
    }


# ---------------------------------------------------------------- CycloneDX


def _cdx_license():
    return [{"license": {"name": NOASSERTION}}]


def _cdx_props(pairs):
    return [{"name": PROP + name, "value": str(value)} for name, value in sorted(pairs)]


def cdx_component(ev):
    base = f"crawlx:identity:chromium:{ev['version']}:{ev['platform']}"
    children = [
        {
            "type": "file",
            "bom-ref": f"{base}:executable",
            "name": "chromium-executable",
            "version": ev["version"],
            "hashes": [{"alg": "SHA-256", "content": ev["executable"]}],
            "licenses": _cdx_license(),
        },
        {
            "type": "file",
            "bom-ref": f"{base}:embedded-notices",
            "name": "chromium-embedded-notices",
            "version": ev["version"],
            "hashes": [{"alg": "SHA-256", "content": ev["notices_sha"]}],
            "licenses": _cdx_license(),
            "properties": _cdx_props(
                [("bytes", ev["notices_bytes"]), ("count", ev["notices_count"])]
            ),
        },
    ]
    for role in ev["roles"]:
        children.append(
            {
                "type": "file",
                "bom-ref": f"{base}:notice:{role['role']}:{role['sha']}",
                "name": f"chromium-notice-{role['role']}",
                "version": ev["version"],
                "hashes": [{"alg": "SHA-256", "content": role["sha"]}],
                "licenses": _cdx_license(),
                "properties": _cdx_props([("role", role["role"]), ("bytes", role["bytes"])]),
            }
        )
    return {
        "type": "application",
        "bom-ref": base,
        "name": "Chromium",
        "version": ev["version"],
        "purl": f"pkg:generic/chromium@{ev['version']}?platform={ev['platform']}",
        "hashes": [{"alg": "SHA-256", "content": ev["archive"]}],
        "licenses": _cdx_license(),
        "externalReferences": [{"type": "distribution", "url": ev["download_url"]}],
        "properties": _cdx_props(
            [
                ("platform", ev["platform"]),
                ("archive-sha256", ev["archive"]),
                ("executable-sha256", ev["executable"]),
                ("embedded-notices-sha256", ev["notices_sha"]),
                ("embedded-notices-bytes", ev["notices_bytes"]),
                ("embedded-notices-count", ev["notices_count"]),
                ("distribution-approval", APPROVAL),
            ]
        ),
        "components": children,
    }


def _walk(node, key):
    """Yield every string value stored under `key` anywhere in `node`."""
    if isinstance(node, dict):
        for k, v in node.items():
            if k == key and isinstance(v, str):
                yield v
            yield from _walk(v, key)
    elif isinstance(node, list):
        for item in node:
            yield from _walk(item, key)


def _merge_cdx(bom, ev):
    components = bom.get("components")
    if components is None:
        components = []
        bom["components"] = components
    elif not isinstance(components, list):
        raise IdentitySbomError("CycloneDX components must be a list")
    ours = cdx_component(ev)
    ours_refs = set(_walk(ours, "bom-ref"))
    existing_top = [c for c in components if isinstance(c, dict) and c.get("bom-ref") == ours["bom-ref"]]
    if existing_top and existing_top[0] == ours and len(existing_top) == 1:
        return  # identical receipt already merged
    clash = ours_refs.intersection(_walk(bom, "bom-ref"))
    if clash:
        raise IdentitySbomError(
            "input already uses identity stable ids with different content: "
            + ", ".join(sorted(clash))
        )
    components.append(ours)


def _strip_cdx(bom, ours_ref):
    out = copy.deepcopy(bom)
    comps = out.get("components")
    if isinstance(comps, list):
        out["components"] = [c for c in comps if not (isinstance(c, dict) and c.get("bom-ref") == ours_ref)]
    return out


# --------------------------------------------------------------------- SPDX


def _spdx_id(suffix):
    return "SPDXRef-CrawlxIdentity-" + suffix


def spdx_packages(ev):
    def package(spdx_id, name, checksum, download, notes):
        return {
            "SPDXID": spdx_id,
            "name": name,
            "versionInfo": ev["version"],
            "downloadLocation": download,
            "filesAnalyzed": False,
            "checksums": [{"algorithm": "SHA256", "checksumValue": checksum}],
            "licenseConcluded": NOASSERTION,
            "licenseDeclared": NOASSERTION,
            "copyrightText": NOASSERTION,
            "attributionTexts": [PROP + f"{k}={v}" for k, v in sorted(notes)],
        }

    engine_id = _spdx_id("Chromium")
    packages = [
        package(
            engine_id,
            "Chromium",
            ev["archive"],
            ev["download_url"],
            [
                ("platform", ev["platform"]),
                ("archive-sha256", ev["archive"]),
                ("executable-sha256", ev["executable"]),
                ("embedded-notices-sha256", ev["notices_sha"]),
                ("embedded-notices-bytes", ev["notices_bytes"]),
                ("embedded-notices-count", ev["notices_count"]),
                ("distribution-approval", APPROVAL),
            ],
        ),
        package(
            _spdx_id("Chromium-Executable"),
            "chromium-executable",
            ev["executable"],
            NOASSERTION,
            [("platform", ev["platform"])],
        ),
        package(
            _spdx_id("Chromium-EmbeddedNotices"),
            "chromium-embedded-notices",
            ev["notices_sha"],
            NOASSERTION,
            [("bytes", ev["notices_bytes"]), ("count", ev["notices_count"])],
        ),
    ]
    for role in ev["roles"]:
        safe = role["role"].replace("_", "-")
        packages.append(
            package(
                _spdx_id(f"Chromium-Notice-{safe}-{role['sha']}"),
                f"chromium-notice-{role['role']}",
                role["sha"],
                NOASSERTION,
                [("role", role["role"]), ("bytes", role["bytes"])],
            )
        )
    relationships = [
        {
            "spdxElementId": engine_id,
            "relationshipType": "CONTAINS",
            "relatedSpdxElement": pkg["SPDXID"],
        }
        for pkg in packages[1:]
    ]
    return packages, relationships


def _merge_spdx(bom, ev):
    packages = bom.get("packages")
    if packages is None:
        packages = []
        bom["packages"] = packages
    elif not isinstance(packages, list):
        raise IdentitySbomError("SPDX packages must be a list")
    relationships = bom.get("relationships")
    if relationships is None:
        relationships = []
        bom["relationships"] = relationships
    elif not isinstance(relationships, list):
        raise IdentitySbomError("SPDX relationships must be a list")

    ours, ours_rels = spdx_packages(ev)
    used = set(_walk(bom, "SPDXID"))
    for pkg in ours:
        present = [p for p in packages if isinstance(p, dict) and p.get("SPDXID") == pkg["SPDXID"]]
        if present:
            if len(present) == 1 and present[0] == pkg:
                continue
            raise IdentitySbomError(
                f"input already uses identity stable id {pkg['SPDXID']} with different content"
            )
        if pkg["SPDXID"] in used:
            raise IdentitySbomError(
                f"input already uses identity stable id {pkg['SPDXID']} outside packages"
            )
        packages.append(pkg)
    for rel in ours_rels:
        if rel not in relationships:
            relationships.append(rel)


def _strip_spdx(bom, ev):
    ours, ours_rels = spdx_packages(ev)
    ids = {p["SPDXID"] for p in ours}
    out = copy.deepcopy(bom)
    if isinstance(out.get("packages"), list):
        out["packages"] = [p for p in out["packages"] if not (isinstance(p, dict) and p.get("SPDXID") in ids)]
    if isinstance(out.get("relationships"), list):
        out["relationships"] = [r for r in out["relationships"] if r not in ours_rels]
    return out


# -------------------------------------------------------------------- merge


def detect_format(bom):
    if not isinstance(bom, dict):
        raise IdentitySbomError("scanner BOM must be a JSON object")
    if bom.get("bomFormat") == "CycloneDX":
        return "cyclonedx"
    version = bom.get("spdxVersion")
    if isinstance(version, str) and version.startswith("SPDX-2."):
        return "spdx"
    raise IdentitySbomError("scanner BOM is neither CycloneDX JSON nor SPDX 2.x JSON")


def merge(bom, ev):
    """Return a new BOM with the identity evidence appended; the input is not mutated."""
    kind = detect_format(bom)
    merged = copy.deepcopy(bom)
    if kind == "cyclonedx":
        _merge_cdx(merged, ev)
        base = f"crawlx:identity:chromium:{ev['version']}:{ev['platform']}"
        restored, expected = _strip_cdx(merged, base), _strip_cdx(bom, base)
        keys = ("components",)
    else:
        _merge_spdx(merged, ev)
        restored, expected = _strip_spdx(merged, ev), _strip_spdx(bom, ev)
        keys = ("packages", "relationships")
    # Every original key/value must survive; only our entries may be added.
    for key in keys:
        if key not in bom and restored.get(key) == []:
            restored.pop(key)
    if restored != expected:
        raise IdentitySbomError("internal error: merge altered scanner content")
    return merged


def render(doc):
    return json.dumps(doc, indent=2, ensure_ascii=False) + "\n"


def write_atomic(path, text):
    path = Path(path)
    directory = path.parent if str(path.parent) else Path(".")
    fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp, 0o644)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise


def run(bom_path, provenance_path, pin_path, output_path):
    bom_path, provenance_path, output_path = map(Path, (bom_path, provenance_path, output_path))
    for other in (bom_path, provenance_path, Path(pin_path)):
        if output_path.exists() and other.exists() and output_path.samefile(other):
            raise IdentitySbomError(f"output must not overwrite input {other}")
    pin = load_pin(pin_path)
    evidence = validate_provenance(load_json(provenance_path), pin)
    merged = merge(load_json(bom_path), evidence)
    write_atomic(output_path, render(merged))
    return hashlib.sha256(render(merged).encode("utf-8")).hexdigest()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("bom", help="scanner CycloneDX or SPDX 2.x JSON (read only)")
    parser.add_argument("--output", required=True, help="merged BOM path (written atomically)")
    parser.add_argument("--provenance", default=str(DEFAULT_PROVENANCE))
    parser.add_argument("--pin", default=str(DEFAULT_PIN))
    args = parser.parse_args(argv)
    try:
        digest = run(args.bom, args.provenance, args.pin, args.output)
    except IdentitySbomError as err:
        print(f"identity-sbom: {err}", file=sys.stderr)
        return 1
    print(f"identity-sbom: wrote {args.output} sha256={digest}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
