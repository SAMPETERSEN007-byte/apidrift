"""Prove `apidrift scan` can FIRE, in every language it claims to read.

"Zero impacts across 22 repositories" is either a measurement or a dead
instrument, and the count cannot tell you which. That question has been asked
here seven times and answered wrongly three of them, so the scan side needs
what the engine side got: a case where the answer is known.

This builds a fixture repository whose code genuinely depends on a REAL
breaking change taken from a real vendor's spec -- not a hand-written finding,
because a hand-written one drifts away from what the engine actually emits and
then proves nothing. The same dependence is written twice, once in Python and
once in TypeScript, and both must be found.

A language whose control does not fire is a language whose "clean" means
nothing, and it is named here rather than averaged into a total.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from apidrift.diff import BREAKING, Finding                  # noqa: E402
from apidrift.cli import analyse                             # noqa: E402
from apidrift.scan import scan_repo                          # noqa: E402
from apidrift.vendors import get                             # noqa: E402

# The SDK client expression per vendor, in each language. Only vendors whose
# JavaScript SDK package is known to `js_dependence` can be written here --
# a fixture that imports a package the prover does not associate with the
# vendor would fail for a reason that has nothing to do with the scan.
CLIENTS: Dict[str, Dict[str, str]] = {
    "stripe": {"py_import": "import stripe",
               "py_call": "stripe.{resource}.retrieve(ident)",
               "ts_import": "import Stripe from 'stripe';\nconst client = new Stripe(key);",
               "ts_call": "client.{resource}.retrieve(ident)"},
    "plaid": {"py_import": "import plaid",
              "py_call": "plaid.{resource}.get(ident)",
              "ts_import": "import { PlaidApi } from 'plaid';\nconst client = new PlaidApi(cfg);",
              "ts_call": "client.{resource}.get(ident)"},
    "openai": {"py_import": "import openai",
               "py_call": "openai.{resource}.retrieve(ident)",
               "ts_import": "import OpenAI from 'openai';\nconst client = new OpenAI();",
               "ts_call": "client.{resource}.retrieve(ident)"},
}


def _wire_leaf(subject: str) -> str:
    """The last step of a subject that is actually on the wire.

    A subject interleaves two alphabets: `.name` and `[]` are what a caller
    writes, `<Name>` is a schema name and is not. Stripping the brackets and
    taking the final dotted segment yields the field, not the schema.
    """
    import re as _re
    plain = _re.sub(r"<[^<>]*>", "", subject)
    return plain.replace("[]", "").split(".")[-1].strip()


def _pick(findings: List[Dict[str, Any]], vendor_key: str) -> Optional[Dict[str, Any]]:
    """A response-side field removal with a name distinctive enough to prove.

    Chosen from what the engine really emitted, so this control cannot quietly
    stop describing the engine.
    """
    for finding in findings:
        if finding["kind"] != "response_field_removed":
            continue
        # The leaf must be what a CALLER writes, and `root_cause` is not that:
        # it is the finding's innermost SCHEMA name. Taking it built a fixture
        # reading `record.subscriptions_trials_resource_trial_settings`, which
        # no caller would ever write, and the control passed only while the
        # prover was equally confused about the difference. The subject keeps
        # the engine's brackets, and the last unbracketed step in it is the
        # wire name -- here `trial_settings`.
        leaf = _wire_leaf(finding.get("subject") or "")
        if len(leaf) < 6 or not leaf.replace("_", "").isalnum():
            continue
        path = finding.get("path") or ""
        if not path.startswith("/"):
            continue
        segments = [s for s in path.split("/") if s and not s.startswith("{")]
        if not segments:
            continue
        return {"finding": finding, "leaf": leaf,
                "resource": segments[-1], "path": path,
                "method": finding.get("method", "GET").lower()}
    return None


def _write_fixture(root: Path, vendor_key: str, case: Dict[str, Any]) -> Dict[str, int]:
    """The same dependence in two languages. Returns {file: expected_line}."""
    client = CLIENTS[vendor_key]
    src = root / "src"
    src.mkdir(parents=True, exist_ok=True)
    resource, leaf, path = case["resource"], case["leaf"], case["path"]

    python = (
        f"{client['py_import']}\n"
        f"\n"
        f"def load(ident):\n"
        f"    # {path}\n"
        f"    record = {client['py_call'].format(resource=resource)}\n"
        f"    return record.{leaf}\n"
    )
    (src / "app.py").write_text(python)

    typescript = (
        f"{client['ts_import']}\n"
        f"\n"
        f"export async function load(ident: string) {{\n"
        f"  // {path}\n"
        f"  const record = await {client['ts_call'].format(resource=resource)};\n"
        f"  return record.{leaf};\n"
        f"}}\n"
    )
    (src / "app.ts").write_text(typescript)
    return {"src/app.py": python.splitlines().index(f"    return record.{leaf}") + 1,
            "src/app.ts": typescript.splitlines().index(f"  return record.{leaf};") + 1}


def run(findings_path: Path, cache: Path, asof: str, days: int,
        vendors: List[str]) -> int:
    # Findings are re-derived from the specs on every run, never read from a
    # file. Reading `out_all/findings.json` meant this control could build a
    # fixture around a finding the engine had since stopped emitting, and then
    # report SILENT -- blaming the scanner for the absence of something nobody
    # was looking for. A control pointed at a stale artifact is worse than no
    # control: it goes red for a reason that has nothing to do with what it
    # measures.
    since = (dt.date.fromisoformat(asof) - dt.timedelta(days=days)).isoformat()
    by_vendor: Dict[str, List[Dict[str, Any]]] = {}
    for key in vendors:
        if key not in CLIENTS:
            continue
        try:
            result = analyse(get(key), cache, since, fetch=False)
        except Exception as exc:                            # noqa: BLE001
            print(f"{key:10} could not diff: {type(exc).__name__}: {exc}"[:110])
            continue
        by_vendor[key] = [f.as_dict() for f in result.findings
                          if f.severity == BREAKING]

    print("Each row: a REAL breaking change, written into a fixture repo as a\n"
          "genuine dependence, in two languages. Both must be found.\n")
    header = f"{'vendor':10} {'field':26} {'python':>10} {'typescript':>12}"
    print(header)
    print("-" * len(header))
    failures: List[str] = []
    ran = 0
    for key in vendors:
        if key not in CLIENTS:
            continue
        case = _pick(by_vendor.get(key, []), key)
        if case is None:
            print(f"{key:10} {'—':26} {'no usable finding in the window':>24}")
            failures.append(f"{key}: no finding to build a control from")
            continue
        ran += 1
        tmp = Path(tempfile.mkdtemp(prefix=f"apidrift-control-{key}-"))
        try:
            _write_fixture(tmp, key, case)
            result = scan_repo(root=tmp, since=since, vendor_keys=[key],
                               cache_dir=cache, fetch=False, asof=asof,
                               window_days=days, progress=None)
            hit = {impact.file for impact in result.breaking}
            py = "FIRED" if "src/app.py" in hit else "SILENT"
            ts = "FIRED" if "src/app.ts" in hit else "SILENT"
            print(f"{key:10} {case['leaf'][:26]:26} {py:>10} {ts:>12}")
            if py != "FIRED":
                failures.append(f"{key}: the PYTHON control did not fire")
            if ts != "FIRED":
                failures.append(f"{key}: the TYPESCRIPT control did not fire")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    print(f"\n{ran} control(s) built from real findings; {len(failures)} problem(s)")
    for line in failures:
        print(f"  {line}")
    if not ran:
        print("  NO CONTROL RAN AT ALL — this is not a pass, it is a failed "
              "measurement of the instrument.")
        return 1
    return 1 if failures else 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="scan_control")
    parser.add_argument("--findings", default=str(ROOT / "out_all" / "findings.json"))
    parser.add_argument("--cache", default=str(ROOT / ".cache"))
    parser.add_argument("--asof", default=dt.date.today().isoformat())
    parser.add_argument("--days", type=int, default=180)
    parser.add_argument("--vendors", default="stripe,plaid,openai")
    args = parser.parse_args(argv)
    return run(Path(args.findings), Path(args.cache), args.asof, args.days,
               [v.strip() for v in args.vendors.split(",") if v.strip()])


if __name__ == "__main__":
    raise SystemExit(main())
