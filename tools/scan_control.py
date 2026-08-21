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
    return (_wire_path(subject) or [""])[-1]


def _wire_path(subject: str) -> List[str]:
    """Every step of a subject that is on the wire, in order.

    🚨 The leaf alone is not enough to build a fixture with, and building one
    from it wrote a read at the WRONG POSITION. Stripe's
    `<radar.payment_evaluation>.insights.card_issuer_decline` produced
    `record.card_issuer_decline`, which is not a read of that field at all --
    the field is at `record.insights.card_issuer_decline`. The control passed
    for as long as the prover made the same mistake, and went SILENT the moment
    the prover learned that a read is a position and not a word. A control
    that chooses its stimulus the way the mechanism under test would is not
    measuring that mechanism.
    """
    import re as _re
    plain = _re.sub(r"<[^<>]*>", "", subject)
    return [step for step in plain.replace("[]", "").split(".") if step.strip()]


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
                "wire_path": _wire_path(finding.get("subject") or ""),
                "resource": segments[-1], "path": path,
                "method": finding.get("method", "GET").lower()}
    return None


def _write_fixture(root: Path, vendor_key: str, case: Dict[str, Any]) -> Dict[str, int]:
    """The same dependence in two languages. Returns {file: expected_line}."""
    client = CLIENTS[vendor_key]
    src = root / "src"
    src.mkdir(parents=True, exist_ok=True)
    resource, leaf, path = case["resource"], case["leaf"], case["path"]
    # The read must sit where the subject says it sits, or this fixture is not
    # a dependence and finding it would prove nothing.
    access = ".".join(case.get("wire_path") or [leaf])

    python = (
        f"{client['py_import']}\n"
        f"\n"
        f"def load(ident):\n"
        f"    # {path}\n"
        f"    record = {client['py_call'].format(resource=resource)}\n"
        f"    return record.{access}\n"
    )
    (src / "app.py").write_text(python)

    typescript = (
        f"{client['ts_import']}\n"
        f"\n"
        f"export async function load(ident: string) {{\n"
        f"  // {path}\n"
        f"  const record = await {client['ts_call'].format(resource=resource)};\n"
        f"  return record.{access};\n"
        f"}}\n"
    )
    (src / "app.ts").write_text(typescript)

    # 🚨 A vendor that serves DATED API versions does not break a caller on an
    # SDK, because the SDK sends the version it shipped with. The two files
    # above are therefore UNMEASURED for Stripe and Plaid, and asking them to
    # fire would be asking the tool to make a claim that is not true. The
    # population that CAN still drift is the caller writing its own request,
    # so that is what the control demands of a versioned vendor -- and it
    # separately demands that the SDK files land in the `pinned` bucket rather
    # than going quiet, because silence and abstention are not the same result.
    host = _api_host(vendor_key)
    raw = (f"import requests\n"
           f"\n"
           f"def load(ident):\n"
           f"    record = requests.get(\n"
           f'        "https://{host}{path}".replace("{{ident}}", ident)\n'
           f"    ).json()\n"
           f"    return record{''.join(f'[{step!r}]' for step in (case.get('wire_path') or [leaf]))}\n")
    (src / "raw.py").write_text(raw)
    return {"src/app.py": python.splitlines().index(f"    return record.{access}") + 1,
            "src/app.ts": typescript.splitlines().index(f"  return record.{access};") + 1}


def _api_host(vendor_key: str) -> str:
    """The vendor's API host, from its own evidence markers."""
    for marker in get(vendor_key).evidence:
        if "." in marker and "/" not in marker and " " not in marker \
                and not marker.endswith("."):
            return marker
    return f"api.{vendor_key}.com"


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
    header = f"{'vendor':10} {'field':26} {'raw/py':>10} {'sdk':>12}"
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
            # Must be THIS finding. Accepting any breaking impact on the file
            # let an unrelated change carry the control: the TypeScript half
            # reported FIRED on a fixture whose read was at the wrong position,
            # because a different Stripe finding also landed on `app.ts`.
            # Compared on the WIRE form: `scan` reports an Impact's subject
            # with the schema annotations already stripped, so
            # `<radar.payment_evaluation>.insights.card_issuer_decline` arrives
            # as `radar.payment_evaluation.insights.card_issuer_decline` and an
            # equality test on the raw subject can never match.
            wanted = _wire_path(case["finding"].get("subject") or "")
            hit = {impact.file for impact in result.breaking
                   if _wire_path(impact.subject)[-len(wanted):] == wanted}
            pinned = set(result.pinned.get(key, ()))
            if get(key).versioned:
                # The SDK files must be ABSTAINED ON, by name, and the raw
                # caller must fire. Either half missing is a failure: a quiet
                # SDK file that is not in `pinned` is the tool going silent for
                # a reason it cannot state.
                py = "FIRED" if "src/raw.py" in hit else "SILENT"
                ts = "PINNED" if {"src/app.py", "src/app.ts"} <= pinned else "LEAKED"
                print(f"{key:10} {case['leaf'][:26]:26} {py:>10} {ts:>12}")
                if py != "FIRED":
                    failures.append(f"{key}: the RAW-HTTP control did not fire")
                if ts != "PINNED":
                    failures.append(f"{key}: an SDK file was neither judged "
                                    f"nor recorded as pinned")
                continue
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
