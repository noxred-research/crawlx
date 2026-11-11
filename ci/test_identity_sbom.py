"""Offline tests for ci/identity-sbom.py."""

import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
SPEC = importlib.util.spec_from_file_location("identity_sbom", HERE / "identity-sbom.py")
TOOL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(TOOL)

VERSION = "155.0.8059.84"
ARCHIVE = "cf0f049892dea22e6a6db26d47ed0d7776b7158edcbec4634086633df8bafcbc"
EXECUTABLE = "b866a2964538c825538c454de4867973b926650da57ec12dc3328807d768247b"
NOTICES = "fc63eda353b7cc0cf797c7d7e5ae823096b8a2d1734f83afb078a405d3a0fb65"
TLS = "c9d230b5b6d2185409a6514aecf416b1198552769a4e8abde47521afc4895010"

PIN = f"""[chromium]
version = "{VERSION}"
os = "linux"
arch = "x86_64"
download_url = "https://example.invalid/{VERSION}/linux64/chrome-linux64.zip"
sha256 = "{ARCHIVE}"
"""

PROVENANCE = {
    "schema": TOOL.SCHEMA,
    "engine": "Chromium",
    "version": VERSION,
    "platform": "linux-x86_64",
    "archiveSha256": ARCHIVE,
    "executableSha256": EXECUTABLE,
    "embeddedNoticesSha256": NOTICES,
    "embeddedNoticesBytes": 8682100,
    "embeddedNoticesCount": 768,
    "roles": [
        {"role": "tls", "noticeSha256": TLS, "noticeBytes": 13114},
        {"role": "compression", "noticeSha256": "3d" * 32, "noticeBytes": 1084},
    ],
    "distributionApproval": "external_required",
}

CDX = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "components": [
        {"type": "library", "bom-ref": "pkg:cargo/serde@1.0.0", "name": "serde", "version": "1.0.0"}
    ],
    "vulnerabilities": [{"id": "CVE-0000-0000", "ratings": [{"severity": "high"}]}],
}

SPDX = {
    "spdxVersion": "SPDX-2.3",
    "SPDXID": "SPDXRef-DOCUMENT",
    "name": "image",
    "packages": [{"SPDXID": "SPDXRef-Package-libc", "name": "libc", "licenseConcluded": "LGPL-2.1-only"}],
    "relationships": [
        {
            "spdxElementId": "SPDXRef-DOCUMENT",
            "relationshipType": "DESCRIBES",
            "relatedSpdxElement": "SPDXRef-Package-libc",
        }
    ],
}


class Fixture(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.dir = Path(self._tmp.name)
        self.pin = self.dir / "chromium-pin.toml"
        self.pin.write_text(PIN, encoding="utf-8")

    def write(self, name, doc):
        path = self.dir / name
        path.write_text(json.dumps(doc), encoding="utf-8")
        return path

    def run_tool(self, bom, provenance=None, out="out.json"):
        bom_path = self.write("bom.json", bom)
        prov_path = self.write("prov.json", PROVENANCE if provenance is None else provenance)
        out_path = self.dir / out
        TOOL.run(bom_path, prov_path, self.pin, out_path)
        return json.loads(out_path.read_text(encoding="utf-8"))

    def rejects(self, bom, provenance=None, pin=None, message=""):
        if pin is not None:
            self.pin.write_text(pin, encoding="utf-8")
        out_path = self.dir / "out.json"
        with self.assertRaises(TOOL.IdentitySbomError) as caught:
            self.run_tool(bom, provenance)
        self.assertIn(message, str(caught.exception))
        self.assertFalse(out_path.exists())
        self.assertEqual([p.name for p in self.dir.glob(".*.tmp")], [])


class CycloneDxTests(Fixture):
    def test_merge_adds_identity_and_keeps_scanner_content(self):
        merged = self.run_tool(CDX)
        self.assertEqual(merged["vulnerabilities"], CDX["vulnerabilities"])
        self.assertEqual(merged["components"][0], CDX["components"][0])
        self.assertEqual(len(merged["components"]), 2)
        engine = merged["components"][1]
        self.assertEqual(engine["name"], "Chromium")
        self.assertEqual(engine["version"], VERSION)
        self.assertEqual(engine["hashes"], [{"alg": "SHA-256", "content": ARCHIVE}])
        self.assertEqual(engine["licenses"], [{"license": {"name": "NOASSERTION"}}])
        props = {p["name"]: p["value"] for p in engine["properties"]}
        self.assertEqual(props["crawlx:identity:distribution-approval"], "external_required")
        self.assertEqual(props["crawlx:identity:executable-sha256"], EXECUTABLE)
        self.assertEqual(props["crawlx:identity:embedded-notices-sha256"], NOTICES)
        self.assertEqual(props["crawlx:identity:embedded-notices-count"], "768")
        self.assertEqual(props["crawlx:identity:platform"], "linux-x86_64")
        children = {c["name"]: c for c in engine["components"]}
        self.assertEqual(children["chromium-executable"]["hashes"][0]["content"], EXECUTABLE)
        self.assertEqual(children["chromium-notice-tls"]["hashes"][0]["content"], TLS)
        self.assertEqual(children["chromium-embedded-notices"]["hashes"][0]["content"], NOTICES)

    def test_output_is_deterministic_and_input_not_mutated(self):
        original = copy.deepcopy(CDX)
        first = self.run_tool(CDX, out="a.json")
        second = self.run_tool(CDX, out="b.json")
        self.assertEqual(first, second)
        self.assertEqual((self.dir / "a.json").read_bytes(), (self.dir / "b.json").read_bytes())
        self.assertEqual(json.loads((self.dir / "bom.json").read_text()), original)

    def test_rerun_on_merged_output_is_idempotent(self):
        once = self.run_tool(CDX)
        twice = self.run_tool(once, out="again.json")
        self.assertEqual(once, twice)

    def test_missing_components_key_is_created(self):
        merged = self.run_tool({"bomFormat": "CycloneDX", "specVersion": "1.5"})
        self.assertEqual(len(merged["components"]), 1)

    def test_conflicting_stable_id_rejected(self):
        merged = self.run_tool(CDX)
        # The first merge only produces the tampered input; its output must not count.
        (self.dir / "out.json").unlink()
        tampered = copy.deepcopy(merged)
        tampered["components"][1]["version"] = "1.0"
        self.rejects(tampered, message="stable ids")

    def test_nested_stable_id_collision_rejected(self):
        bom = copy.deepcopy(CDX)
        ref = f"crawlx:identity:chromium:{VERSION}:linux-x86_64:executable"
        bom["components"][0]["components"] = [{"type": "file", "bom-ref": ref, "name": "x"}]
        self.rejects(bom, message="stable ids")


class SpdxTests(Fixture):
    def test_merge_adds_packages_and_keeps_scanner_content(self):
        merged = self.run_tool(SPDX)
        self.assertEqual(merged["packages"][0], SPDX["packages"][0])
        self.assertEqual(merged["relationships"][0], SPDX["relationships"][0])
        by_name = {p["name"]: p for p in merged["packages"]}
        engine = by_name["Chromium"]
        self.assertEqual(engine["checksums"], [{"algorithm": "SHA256", "checksumValue": ARCHIVE}])
        self.assertEqual(engine["licenseConcluded"], "NOASSERTION")
        self.assertEqual(engine["licenseDeclared"], "NOASSERTION")
        self.assertIn("crawlx:identity:distribution-approval=external_required", engine["attributionTexts"])
        self.assertEqual(by_name["chromium-executable"]["checksums"][0]["checksumValue"], EXECUTABLE)
        self.assertEqual(by_name["chromium-notice-tls"]["checksums"][0]["checksumValue"], TLS)
        contained = {
            r["relatedSpdxElement"]
            for r in merged["relationships"]
            if r["relationshipType"] == "CONTAINS" and r["spdxElementId"] == engine["SPDXID"]
        }
        self.assertEqual(len(contained), len(merged["packages"]) - 2)
        ids = [p["SPDXID"] for p in merged["packages"]]
        self.assertEqual(len(ids), len(set(ids)))

    def test_rerun_is_idempotent(self):
        once = self.run_tool(SPDX)
        twice = self.run_tool(once, out="again.json")
        self.assertEqual(once, twice)

    def test_conflicting_stable_id_rejected(self):
        merged = self.run_tool(SPDX)
        # The first merge only produces the tampered input; its output must not count.
        (self.dir / "out.json").unlink()
        tampered = copy.deepcopy(merged)
        for pkg in tampered["packages"]:
            if pkg["name"] == "Chromium":
                pkg["checksums"][0]["checksumValue"] = "0" * 64
        self.rejects(tampered, message="different content")

    def test_unknown_format_rejected(self):
        self.rejects({"spdxVersion": "SPDX-3.0"}, message="neither CycloneDX")
        self.rejects([], message="JSON object")


class EvidenceTests(Fixture):
    def mutated(self, **changes):
        doc = copy.deepcopy(PROVENANCE)
        doc.update(changes)
        return doc

    def test_wrong_hashes_rejected(self):
        for key in ("archiveSha256", "executableSha256", "embeddedNoticesSha256"):
            for bad in ("abc", ARCHIVE.upper(), "g" * 64, ARCHIVE + "0", 7):
                with self.subTest(key=key, bad=bad):
                    self.rejects(CDX, self.mutated(**{key: bad}))

    def test_archive_not_matching_pin_rejected(self):
        self.rejects(CDX, self.mutated(archiveSha256="1" * 64), message="pinned archive")

    def test_pin_version_and_platform_mismatch_rejected(self):
        self.rejects(CDX, self.mutated(version="155.0.0.1"), message="does not match pin")
        self.rejects(CDX, self.mutated(platform="linux-aarch64"), message="does not match pin")

    def test_pin_changes_are_detected(self):
        self.rejects(CDX, pin=PIN.replace(VERSION, "156.0.0.1"), message="does not match pin")

    def test_bad_pin_rejected(self):
        self.rejects(CDX, pin=PIN.replace(ARCHIVE, "xyz"), message="pin [chromium].sha256")
        self.rejects(CDX, pin="[other]\n", message="no [chromium]")

    def test_approval_must_stay_external_required(self):
        for value in ("approved", "", None):
            self.rejects(CDX, self.mutated(distributionApproval=value), message="external_required")

    def test_unknown_keys_and_missing_keys_rejected(self):
        self.rejects(CDX, self.mutated(wireEquivalent=True), message="keys mismatch")
        doc = self.mutated()
        del doc["executableSha256"]
        self.rejects(CDX, doc, message="keys mismatch")

    def test_role_validation(self):
        good = PROVENANCE["roles"][0]
        for roles in (
            [],
            [dict(good, role="vendor-x")],
            [dict(good, noticeSha256="zz")],
            [dict(good, noticeBytes=0)],
            [dict(good, noticeBytes=True)],
            [good, copy.deepcopy(good)],
            [good, dict(good, role="compression", noticeBytes=1)],
            [dict(good, extra=1)],
        ):
            with self.subTest(roles=roles):
                self.rejects(CDX, self.mutated(roles=roles))

    def test_counts_must_be_positive_integers(self):
        for key in ("embeddedNoticesBytes", "embeddedNoticesCount"):
            for bad in (0, -1, "1", 1.5, True):
                with self.subTest(key=key, bad=bad):
                    self.rejects(CDX, self.mutated(**{key: bad}))


class FileHandlingTests(Fixture):
    def test_duplicate_json_keys_in_scanner_input_rejected(self):
        bom_path = self.dir / "bom.json"
        bom_path.write_text('{"bomFormat": "CycloneDX", "bomFormat": "CycloneDX"}', encoding="utf-8")
        prov = self.write("prov.json", PROVENANCE)
        with self.assertRaises(TOOL.IdentitySbomError):
            TOOL.run(bom_path, prov, self.pin, self.dir / "out.json")

    def test_output_cannot_overwrite_input(self):
        bom_path = self.write("bom.json", CDX)
        prov = self.write("prov.json", PROVENANCE)
        for target in (bom_path, prov, self.pin):
            before = target.read_bytes()
            with self.assertRaises(TOOL.IdentitySbomError):
                TOOL.run(bom_path, prov, self.pin, target)
            self.assertEqual(target.read_bytes(), before)

    def test_failed_run_leaves_existing_output_untouched(self):
        out = self.dir / "out.json"
        out.write_text("previous", encoding="utf-8")
        bom_path = self.write("bom.json", CDX)
        prov = self.write("prov.json", dict(PROVENANCE, archiveSha256="2" * 64))
        with self.assertRaises(TOOL.IdentitySbomError):
            TOOL.run(bom_path, prov, self.pin, out)
        self.assertEqual(out.read_text(encoding="utf-8"), "previous")

    def test_main_returns_status(self):
        bom_path = self.write("bom.json", SPDX)
        prov = self.write("prov.json", PROVENANCE)
        out = self.dir / "out.json"
        args = [str(bom_path), "--output", str(out), "--provenance", str(prov), "--pin", str(self.pin)]
        self.assertEqual(TOOL.main(args), 0)
        self.assertTrue(out.exists())
        bad = self.write("prov.json", dict(PROVENANCE, version="1"))
        self.assertEqual(TOOL.main(args[:3] + ["--provenance", str(bad), "--pin", str(self.pin)]), 1)


class RepositoryEvidenceTests(unittest.TestCase):
    def test_committed_provenance_matches_committed_pin(self):
        pin = TOOL.load_pin(ROOT / "chromium-pin.toml")
        evidence = TOOL.validate_provenance(
            TOOL.load_json(ROOT / "docs" / "identity-profile-provenance.json"), pin
        )
        self.assertEqual(evidence["version"], VERSION)
        self.assertEqual(evidence["archive"], ARCHIVE)
        self.assertEqual(evidence["executable"], EXECUTABLE)
        self.assertEqual(evidence["notices_sha"], NOTICES)
        self.assertEqual(evidence["notices_bytes"], 8682100)
        self.assertEqual(evidence["notices_count"], 768)
        self.assertEqual(len(evidence["roles"]), 7)
        roles = {r["role"] for r in evidence["roles"]}
        self.assertEqual(roles, {"tls", "compression", "ca_or_transport_notice"})


if __name__ == "__main__":
    unittest.main()
