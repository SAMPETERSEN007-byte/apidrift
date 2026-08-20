"""Semantic breaking-change detection between two versions of an OpenAPI spec."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from .loader import Field, Operation, Param, Spec

BREAKING = "breaking"
POTENTIALLY_BREAKING = "potentially_breaking"
ADDITIVE = "additive"

SEVERITY_RANK = {BREAKING: 0, POTENTIALLY_BREAKING: 1, ADDITIVE: 2}


@dataclass
class Finding:
    kind: str
    severity: str
    op_key: str
    path: str
    method: str
    detail: str
    subject: str = ""          # param name / field path / status code
    old: str = ""
    new: str = ""
    operation_id: Optional[str] = None
    signatures: List[str] = field(default_factory=list)
    grep: str = ""
    github_search: str = ""
    spec_file: str = ""
    occurrences: int = 1
    affected_op_count: int = 0
    affected_ops: List[str] = field(default_factory=list)
    root_cause: str = ""

    def as_dict(self) -> Dict[str, object]:
        return {
            "kind": self.kind,
            "severity": self.severity,
            "spec_file": self.spec_file,
            "op_key": self.op_key,
            "path": self.path,
            "method": self.method.upper(),
            "operation_id": self.operation_id,
            "subject": self.subject,
            "old": self.old,
            "new": self.new,
            "detail": self.detail,
            "occurrences": self.occurrences,
            "affected_op_count": self.affected_op_count,
            "root_cause": self.root_cause,
            "affected_ops": self.affected_ops[:25],
            "signatures": self.signatures,
            "grep": self.grep,
            "github_search": self.github_search,
        }


@dataclass
class DiffResult:
    vendor: str
    old_ref: str
    new_ref: str
    old_date: str
    new_date: str
    old_op_count: int = 0
    new_op_count: int = 0
    specs_matched: int = 0
    specs_changed: int = 0
    raw_finding_count: int = 0
    findings: List[Finding] = field(default_factory=list)

    def by_severity(self, severity: str) -> List[Finding]:
        return [f for f in self.findings if f.severity == severity]

    @property
    def breaking(self) -> List[Finding]:
        return self.by_severity(BREAKING)

    @property
    def potentially_breaking(self) -> List[Finding]:
        return self.by_severity(POTENTIALLY_BREAKING)



def _blind(path: str) -> str:
    """Erase the identity of anonymous union arms.

    An arm named for a real schema (`<Card>`) keeps its identity. One named by
    a content fingerprint (`<enum-3410da5c>`) or a bare primitive (`<integer>`)
    is anonymous: editing it renames it, so the name cannot be compared.
    """
    return _ARM.sub(
        lambda m: m.group(0) if _is_nameable(m.group(1)) else "<*>", path
    )


def _synthetic_parent(path: str) -> str:
    """The path up to the outermost anonymous arm — i.e. what actually changed."""
    for mark in reversed(list(_ARM.finditer(path))):
        if not _is_nameable(mark.group(1)):
            return path[:mark.start()]
    return path


def _mk(op: Operation, kind: str, severity: str, detail: str, **kw) -> Finding:
    return Finding(
        kind=kind,
        severity=severity,
        op_key=op.key,
        path=op.path,
        method=op.method,
        operation_id=op.operation_id,
        detail=detail,
        **kw,
    )


def _diff_params(old: Operation, new: Operation) -> List[Finding]:
    out: List[Finding] = []
    for key, p_old in old.params.items():
        p_new = new.params.get(key)
        if p_new is None:
            sev = BREAKING if p_old.location == "path" else POTENTIALLY_BREAKING
            out.append(_mk(
                new, "param_removed", sev,
                f"{p_old.location} parameter `{p_old.name}` was removed",
                subject=p_old.name, old=p_old.type, new="<removed>",
            ))
            continue
        if not p_old.required and p_new.required:
            out.append(_mk(
                new, "param_now_required", BREAKING,
                f"{p_new.location} parameter `{p_new.name}` became required",
                subject=p_new.name, old="optional", new="required",
            ))
        if p_old.type != p_new.type:
            out.append(_mk(
                new, "param_type_changed", BREAKING,
                f"{p_new.location} parameter `{p_new.name}` changed type",
                subject=p_new.name, old=p_old.type, new=p_new.type,
            ))
        if p_old.enum and p_new.enum:
            dropped = sorted(set(p_old.enum) - set(p_new.enum))
            if dropped:
                out.append(_mk(
                    new, "request_enum_value_removed", BREAKING,
                    f"parameter `{p_new.name}` no longer accepts: {', '.join(dropped)}",
                    subject=p_new.name, old="|".join(p_old.enum), new="|".join(p_new.enum),
                ))
        if not p_old.deprecated and p_new.deprecated:
            out.append(_mk(
                new, "param_deprecated", POTENTIALLY_BREAKING,
                f"{p_new.location} parameter `{p_new.name}` was deprecated",
                subject=p_new.name, old="active", new="deprecated",
            ))

    for key, p_new in new.params.items():
        if key in old.params:
            continue
        if p_new.required:
            out.append(_mk(
                new, "param_added_required", BREAKING,
                f"new required {p_new.location} parameter `{p_new.name}`",
                subject=p_new.name, old="<absent>", new=p_new.type,
            ))
    return out


def _diff_fields(
    old_fields: Dict[str, Field],
    new_fields: Dict[str, Field],
    op: Operation,
    where: str,          # "request" | "response"
    status: str = "",
) -> List[Finding]:
    out: List[Finding] = []
    label = f"response {status}" if where == "response" else "request body"

    # An anonymous union arm is fingerprinted by its contents, so editing the
    # arm changes its name. Without this index, `service_tier<enum-abc>` losing
    # a value reads as the whole subtree being deleted rather than reshaped.
    new_blind: Dict[str, List[Tuple[str, Field]]] = {}
    for key, val in new_fields.items():
        new_blind.setdefault(_blind(key), []).append((key, val))
    old_blind = {_blind(key) for key in old_fields}
    reshaped: Set[str] = set()

    for name, f_old in old_fields.items():
        f_new = new_fields.get(name)
        if f_new is None:
            blind = _blind(name)
            if blind != name and blind in new_blind:
                parent = _synthetic_parent(name)
                if parent in reshaped:
                    continue
                reshaped.add(parent)
                _, counterpart = new_blind[blind][0]
                display = parent or "<root>"
                if f_old.enum and counterpart.enum:
                    dropped = sorted(set(f_old.enum) - set(counterpart.enum))
                    added = sorted(set(counterpart.enum) - set(f_old.enum))
                    if dropped:
                        out.append(_mk(
                            op, f"{where}_enum_value_removed",
                            BREAKING if where == "request" else POTENTIALLY_BREAKING,
                            f"{label} field `{display}` dropped values: {', '.join(dropped)}",
                            subject=parent, old="|".join(f_old.enum),
                            new="|".join(counterpart.enum),
                        ))
                    if added and where == "response":
                        out.append(_mk(
                            op, "response_enum_value_added", POTENTIALLY_BREAKING,
                            f"{label} field `{display}` gained values: {', '.join(added)} "
                            f"(exhaustive switches will fall through)",
                            subject=parent, old="|".join(f_old.enum),
                            new="|".join(counterpart.enum),
                        ))
                    if added and where == "request":
                        continue
                elif f_old.type != counterpart.type:
                    out.append(_mk(
                        op, f"{where}_field_type_changed", BREAKING,
                        f"{label} field `{display}` changed shape",
                        subject=parent, old=f_old.type, new=counterpart.type,
                    ))
                continue
            kind = "request_field_removed" if where == "request" else "response_field_removed"
            # Losing a response field breaks every consumer reading it.
            # Losing a request field is usually ignored server-side.
            sev = BREAKING if where == "response" else POTENTIALLY_BREAKING
            out.append(_mk(
                op, kind, sev,
                f"{label} field `{name}` was removed",
                subject=name, old=f_old.signature(), new="<removed>",
            ))
            continue
        if f_old.type != f_new.type:
            out.append(_mk(
                op, f"{where}_field_type_changed", BREAKING,
                f"{label} field `{name}` changed type",
                subject=name, old=f_old.type, new=f_new.type,
            ))
        if where == "request" and not f_old.required and f_new.required:
            out.append(_mk(
                op, "request_field_now_required", BREAKING,
                f"{label} field `{name}` became required",
                subject=name, old="optional", new="required",
            ))
        if where == "response" and not f_old.nullable and f_new.nullable:
            out.append(_mk(
                op, "response_field_now_nullable", POTENTIALLY_BREAKING,
                f"{label} field `{name}` became nullable",
                subject=name, old="non-null", new="nullable",
            ))
        if f_old.enum and f_new.enum:
            dropped = sorted(set(f_old.enum) - set(f_new.enum))
            added = sorted(set(f_new.enum) - set(f_old.enum))
            if dropped:
                sev = BREAKING if where == "request" else POTENTIALLY_BREAKING
                out.append(_mk(
                    op, f"{where}_enum_value_removed", sev,
                    f"{label} field `{name}` dropped values: {', '.join(dropped)}",
                    subject=name, old="|".join(f_old.enum), new="|".join(f_new.enum),
                ))
            if added and where == "response":
                out.append(_mk(
                    op, "response_enum_value_added", POTENTIALLY_BREAKING,
                    f"{label} field `{name}` gained values: {', '.join(added)} "
                    f"(exhaustive switches will fall through)",
                    subject=name, old="|".join(f_old.enum), new="|".join(f_new.enum),
                ))

    for name, f_new in new_fields.items():
        if name in old_fields:
            continue
        if _blind(name) != name and _blind(name) in old_blind:
            continue  # same arm, re-fingerprinted — already reported as a reshape
        if where == "request" and f_new.required:
            out.append(_mk(
                op, "request_field_added_required", BREAKING,
                f"{label} gained required field `{name}`",
                subject=name, old="<absent>", new=f_new.signature(),
            ))
    return out


def _diff_operation(old: Operation, new: Operation) -> List[Finding]:
    out: List[Finding] = []
    out.extend(_diff_params(old, new))
    out.extend(_diff_fields(old.request_fields, new.request_fields, new, "request"))

    if not old.request_required and new.request_required:
        out.append(_mk(
            new, "request_body_now_required", BREAKING,
            "request body became required",
            subject="<body>", old="optional", new="required",
        ))

    for status, old_resp in old.responses.items():
        new_resp = new.responses.get(status)
        if new_resp is None:
            if status.startswith("2"):
                out.append(_mk(
                    new, "response_status_removed", BREAKING,
                    f"success response `{status}` was removed",
                    subject=status, old=status, new="<removed>",
                ))
            continue
        out.extend(_diff_fields(old_resp, new_resp, new, "response", status))

    if set(new.security) - set(old.security):
        out.append(_mk(
            new, "security_requirement_added", BREAKING,
            "operation now requires additional auth: "
            + ", ".join(sorted(set(new.security) - set(old.security))),
            subject="<security>",
            old=",".join(old.security) or "<none>",
            new=",".join(new.security) or "<none>",
        ))

    if not old.deprecated and new.deprecated:
        out.append(_mk(
            new, "endpoint_deprecated", POTENTIALLY_BREAKING,
            "operation was marked deprecated",
            subject="<operation>", old="active", new="deprecated",
        ))
    return out


def _match_renamed(
    removed: Dict[str, Operation], added: Dict[str, Operation]
) -> Dict[str, str]:
    """Match removed->added ops that share an operationId (a rename, not a removal)."""
    by_id = {}
    for key, op in added.items():
        if op.operation_id:
            by_id.setdefault(op.operation_id, key)
    matches: Dict[str, str] = {}
    for key, op in removed.items():
        if op.operation_id and op.operation_id in by_id:
            matches[key] = by_id[op.operation_id]
    return matches


def diff_specs(vendor: str, old: Spec, new: Spec, meta: Dict[str, str]) -> DiffResult:
    result = DiffResult(
        vendor=vendor,
        old_ref=meta.get("old_ref", ""),
        new_ref=meta.get("new_ref", ""),
        old_date=meta.get("old_date", ""),
        new_date=meta.get("new_date", ""),
        old_op_count=old.op_count,
        new_op_count=new.op_count,
    )
    findings: List[Finding] = []

    old_keys = set(old.operations)
    new_keys = set(new.operations)

    removed = {k: old.operations[k] for k in old_keys - new_keys}
    added = {k: new.operations[k] for k in new_keys - old_keys}
    renames = _match_renamed(removed, added)

    for key, op in removed.items():
        if key in renames:
            new_op = new.operations[renames[key]]
            findings.append(_mk(
                op, "endpoint_moved", BREAKING,
                f"operation `{op.operation_id}` moved to `{new_op.key}`",
                subject=op.operation_id or key, old=key, new=new_op.key,
            ))
            continue
        findings.append(_mk(
            op, "endpoint_removed", BREAKING,
            "endpoint was removed",
            subject=op.path, old=key, new="<removed>",
        ))

    for key in sorted(old_keys & new_keys):
        findings.extend(_diff_operation(old.operations[key], new.operations[key]))

    old_servers, new_servers = set(old.servers), set(new.servers)
    if old_servers and new_servers and not (old_servers & new_servers):
        pseudo = Operation(path="/", method="get", operation_id=None,
                           summary="", deprecated=False)
        findings.append(_mk(
            pseudo, "server_url_changed", BREAKING,
            "base server URL changed with no overlap",
            subject="<server>",
            old=", ".join(sorted(old_servers)), new=", ".join(sorted(new_servers)),
        ))

    for name in sorted(set(old.security_schemes) - set(new.security_schemes)):
        pseudo = Operation(path="/", method="get", operation_id=None,
                           summary="", deprecated=False)
        findings.append(_mk(
            pseudo, "security_scheme_removed", BREAKING,
            f"security scheme `{name}` was removed",
            subject=name, old=old.security_schemes[name], new="<removed>",
        ))

    findings.sort(key=lambda f: (SEVERITY_RANK[f.severity], f.path, f.method, f.kind, f.subject))
    result.findings = findings
    return result


_ARM = re.compile(r"<([^>]+)>")

_PRIMITIVE_ARMS = frozenset({
    "string", "integer", "number", "boolean", "object", "array", "any",
    "null", "external", "oneOf", "anyOf",
})
_SYNTHETIC_PREFIXES = ("shape-", "enum-", "type=", "kind=", "object=", "idx")


def _is_nameable(arm: str) -> bool:
    """True when an arm name identifies a schema a human would recognise."""
    base = arm.split("~", 1)[0]
    if base in _PRIMITIVE_ARMS:
        return False
    return not base.startswith(_SYNTHETIC_PREFIXES)


def root_cause_key(subject: str) -> str:
    """Reduce a response path to the schema change that actually caused it.

    `error.source<card>.iin`, `<card>.iin` and
    `customer<customer>.default_source<card>.iin` are one change to the shared
    `card` schema reached three ways. Keying on the innermost named schema plus
    the remaining field path collapses them into one root cause.
    """
    marks = list(_ARM.finditer(subject))
    if not marks:
        return subject
    # Walk right-to-left for the innermost marker that names a real schema.
    # `<Response>.service_tier<enum-3410da5c>` is one change to `Response`, not
    # to an anonymous enum, so synthetic markers are not valid root causes.
    for mark in reversed(marks):
        if _is_nameable(mark.group(1)):
            # Everything to the right of the innermost *named* schema is
            # synthetic by construction, so those markers carry no identity.
            suffix = _ARM.sub("", subject[mark.end():]).strip(".")
            return f"{mark.group(1)}.{suffix}" if suffix else mark.group(1)
    # Every marker is synthetic: strip them all and key on the field path.
    return _ARM.sub("", subject).replace("..", ".").strip(".") or subject


def collapse(findings: List[Finding], max_ops: int = 200) -> List[Finding]:
    """Group findings that share one root cause into a single finding.

    A shared schema in a large spec fans one edit out across hundreds of
    operations. Reporting each one separately is how an alerting product gets
    muted; the fan-out count is the useful signal, not the repetition.
    """
    groups: Dict[Tuple[str, str, str, str], List[Finding]] = {}
    order: List[Tuple[str, str, str, str]] = []
    for finding in findings:
        key = (finding.kind, root_cause_key(finding.subject), finding.old, finding.new)
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append(finding)

    collapsed: List[Finding] = []
    for key in order:
        members = groups[key]
        # Keep the shortest path as representative: it is the most direct route
        # to the changed schema and reads best in a report.
        rep = min(members, key=lambda f: (len(f.subject), f.op_key))
        rep.occurrences = len(members)
        rep.root_cause = key[1]
        # `occurrences` counts distinct paths through the spec that reach this
        # change; several of them can land on the same operation. Reporting the
        # occurrence count as an operation count produced "853 operations" for
        # a spec containing 589, which is wrong on its face.
        distinct_ops = {m.op_key for m in members}
        rep.affected_op_count = len(distinct_ops)
        rep.affected_ops = sorted(distinct_ops)[:max_ops]
        if len(distinct_ops) > 1:
            rep.detail = f"{rep.detail} — affects {len(distinct_ops)} operations"
        elif len(members) > 1:
            rep.detail = (f"{rep.detail} — reached {len(members)} ways through "
                          f"1 operation")
        collapsed.append(rep)
    return collapsed
