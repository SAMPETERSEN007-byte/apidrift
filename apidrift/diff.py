"""Semantic breaking-change detection between two versions of an OpenAPI spec."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Set, Tuple

from .loader import TRUNCATED, Field, Operation, Param, Spec

# How each kind must be searched for and verified. Defined here, where kinds
# are created, and imported everywhere else: three modules previously kept
# private copies of these lists and none of them learned about `schema_*`.
ENDPOINT_KINDS = frozenset({
    "endpoint_removed", "endpoint_moved", "spec_removed",
    "response_status_removed", "security_requirement_added",
    "server_url_changed", "schema_removed", "endpoint_deprecated",
})

# The break is the ABSENCE of the field, so the caller is found by the endpoint
# and convicted by not mentioning it.
ABSENCE_KINDS = frozenset({
    "request_field_added_required", "request_field_now_required",
    "param_added_required", "param_now_required", "request_body_now_required",
    "schema_field_added_required", "schema_field_now_required",
})

# The break is the PRESENCE of a field the caller reads or sends.
FIELD_KINDS = frozenset({
    "response_field_removed", "request_field_removed", "schema_field_removed",
    "response_field_type_changed", "request_field_type_changed",
    "schema_field_type_changed",
    "param_removed", "param_type_changed", "param_deprecated",
    "response_enum_value_added", "response_enum_value_removed",
    "request_enum_value_removed",
    "schema_enum_value_added", "schema_enum_value_removed",
    "schema_field_now_nullable", "response_field_now_nullable",
})

# Human labels for the report. The kind is the stable identifier; this is what
# a reader who does not work on this tool should see.
KIND_LABEL = {
    "schema_removed": "schema deleted",
    "schema_field_removed": "field removed from a schema",
    "schema_field_type_changed": "field changed type",
    "schema_field_now_required": "field became required",
    "schema_field_added_required": "new required field",
    "schema_enum_value_removed": "enum value removed",
    "schema_enum_value_added": "enum value added",
    "schema_field_now_nullable": "field became nullable",
    "endpoint_removed": "endpoint removed",
    "endpoint_moved": "endpoint moved",
    "endpoint_deprecated": "endpoint deprecated",
    "spec_removed": "spec file deleted",
    "response_status_removed": "success response removed",
    "response_field_removed": "field removed from a response",
    "request_field_removed": "field removed from a request",
    "response_field_type_changed": "response field changed type",
    "request_field_type_changed": "request field changed type",
    "request_field_added_required": "new required request field",
    "request_field_now_required": "request field became required",
    "response_enum_value_added": "enum value added to a response",
    "response_enum_value_removed": "enum value removed from a response",
    "request_enum_value_removed": "enum value removed from a request",
    "security_requirement_added": "new auth requirement",
    "param_removed": "parameter removed",
    "param_added_required": "new required parameter",
    "param_now_required": "parameter became required",
    "param_type_changed": "parameter changed type",
    "param_deprecated": "parameter deprecated",
    "server_url_changed": "base URL changed",
    "request_body_now_required": "request body became required",
}


def label_for(kind: str) -> str:
    return KIND_LABEL.get(kind, kind.replace("_", " "))


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
    direct_op_count: int = 0
    affected_ops: List[str] = field(default_factory=list)
    # For a whole-schema deletion: the schema's own property names. A caller
    # who reaches the operation but never reads one of these is unaffected,
    # which was seven of ten refutations in the third adversarial audit.
    leaf_fields: List[str] = field(default_factory=list)
    # Which direction the schema travels. A field a caller SENDS is
    # proven by a keyword argument, not by a read, and the two routes
    # cannot be told apart from the finding's kind alone: OpenAI's
    # request body is named `ResponseProperties`.
    in_request: bool = False
    in_response: bool = False
    # The resource an addition belongs to, used to judge whether a
    # repo already working with it would care.
    resource: str = ""
    # The vendor's own sentence about the added field. Only ever populated for
    # additions: a suggestion has to say what the thing is FOR.
    blurb: str = ""
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
            "direct_op_count": self.direct_op_count,
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
    # Why a removal was NOT reported, counted by reason. Never a silent drop:
    # a suppressor that cannot say how often it fired is indistinguishable
    # from an engine that never found anything.
    suppressed: Dict[str, int] = field(default_factory=dict)
    # Spec files that did not exist at the start of the window. Nothing before
    # them could be compared, so a "0 breaking changes" over the requested
    # range is a claim about a period the tool could not see. OpenAI's repo
    # held only a LICENSE 180 days ago and the spec landed 2026-05-13; the
    # honest answer is "visible from 2026-05-13", not "clean since February".
    specs_without_history: List[str] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    # Additions kept apart from findings on purpose. "What can I now use?"
    # is not a weaker version of "what did you take away?" -- it has a
    # different proof (relevance, not dependence) and a different urgency,
    # and folding it in would change every severity count downstream.
    additions: List[Finding] = field(default_factory=list)

    def by_severity(self, severity: str) -> List[Finding]:
        return [f for f in self.findings if f.severity == severity]

    @property
    def breaking(self) -> List[Finding]:
        return self.by_severity(BREAKING)

    @property
    def potentially_breaking(self) -> List[Finding]:
        return self.by_severity(POTENTIALLY_BREAKING)

    @property
    def history_is_short(self) -> bool:
        """True when some spec has no version before the window opened."""
        return bool(self.specs_without_history)



_ROOT_MARKER = re.compile(r"^<[^>]+>\.?")
_SEGMENT = re.compile(r"[.\[<]")


def _segments(path: str) -> int:
    """How many hops from the root this field path represents."""
    return len([p for p in _SEGMENT.split(_strip_root_marker(path)) if p])


def _strip_root_marker(path: str) -> str:
    """Drop a leading `<Schema>` marker.

    The root marker names the schema the whole body or response IS, not a field
    inside it. When a vendor moves a request body from an inline schema to a
    `$ref` — OpenAI did exactly this to `POST /batches` — the old side has
    `completion_window` and the new side has `<CreateBatchRequest>.completion_window`.
    Comparing those literally reports every field as removed AND as newly
    required, which is a fabricated breaking change in both directions.
    """
    return _ROOT_MARKER.sub("", path, count=1)


def _blind(path: str) -> str:
    """Erase identity that is about the schema rather than about the field.

    That means the root marker (see above) and anonymous union arms. An interior
    arm named for a real schema (`<Card>`) keeps its identity, because there it
    distinguishes which member of a union the field belongs to.
    """
    return _ARM.sub(
        lambda m: m.group(0) if _is_nameable(m.group(1)) else "<*>",
        _strip_root_marker(path),
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


# A path parameter is POSITIONAL: its name is substituted into the URL and
# never sent. So a path parameter appearing or disappearing by NAME is either
# a rename (the URL is unchanged) or a genuine change of path shape -- and the
# second is already reported by comparing the path templates themselves. Twilio
# renaming `{ConversationSid}` to `{ConversationId}` produced a `param_removed`
# and a `param_added_required` for one edit that breaks nobody.
def _is_positional(param: Param) -> bool:
    return param.location == "path"


def _diff_params(old: Operation, new: Operation) -> List[Finding]:
    out: List[Finding] = []
    for key, p_old in old.params.items():
        p_new = new.params.get(key)
        if p_new is None:
            if _is_positional(p_old):
                continue      # renamed, or already reported as a moved path
            out.append(_mk(
                new, "param_removed", POTENTIALLY_BREAKING,
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
        if _is_positional(p_new):
            continue          # the other half of the same rename
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

    # Where either side stopped flattening, absence is ignorance, not deletion.
    #
    # Prefix matching alone is not enough. When one version nests one level
    # deeper, the two sides truncate at different *paths*, so the deeper side's
    # marker need not prefix the shallower side's field. The defensible rule is
    # a depth bound: below the shallowest point where a side stopped looking,
    # that side cannot support a claim about anything.
    new_cut_depth = min((_segments(k) for k, v in new_fields.items()
                         if v.type == TRUNCATED), default=None)
    old_cut_depth = min((_segments(k) for k, v in old_fields.items()
                         if v.type == TRUNCATED), default=None)

    def _beyond(path: str, cut_depth: Optional[int]) -> bool:
        return cut_depth is not None and _segments(path) >= cut_depth

    for name, f_old in old_fields.items():
        if f_old.type == TRUNCATED:
            continue  # a marker, not a field
        f_new = new_fields.get(name)
        if f_new is not None and f_new.type == TRUNCATED:
            continue  # the new side was not walked this far
        if f_new is None and _beyond(name, new_cut_depth):
            continue  # absent only because flattening stopped short
        if f_new is None:
            blind = _blind(name)
            # No `blind != name` guard: the marker may sit on the NEW side only,
            # as it does when a body moves from an inline schema to a `$ref`.
            # Reaching here already means `name` itself is absent from the new
            # side, so a blind hit is always a different key reshaped.
            if blind in new_blind:
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
                # A reshape must not swallow a real tightening of the contract.
                if where == "request" and not f_old.required and counterpart.required:
                    out.append(_mk(
                        op, "request_field_now_required", BREAKING,
                        f"{label} field `{name}` became required",
                        subject=name, old="optional", new="required",
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
        if f_new.type == TRUNCATED or name in old_fields:
            continue
        if _beyond(name, old_cut_depth):
            continue  # the old side was not walked this far
        if _blind(name) in old_blind:
            continue  # same field reshaped or re-rooted — already accounted for
        if where == "request" and f_new.required:
            out.append(_mk(
                op, "request_field_added_required", BREAKING,
                f"{label} gained required field `{name}`",
                subject=name, old="<absent>", new=f_new.signature(),
            ))
    return out


def _render_security(alternatives: Sequence[frozenset]) -> str:
    if not alternatives:
        return "<none>"
    return " OR ".join("+".join(sorted(alt)) or "<empty>" for alt in alternatives)


def _security_tightened(
    old: Sequence[frozenset], new: Sequence[frozenset],
) -> Tuple[bool, str]:
    """Did the contract get harder to satisfy?

    A caller who satisfied some old alternative is still fine if any NEW
    alternative is a subset of what they already provide. Adding a further
    alternative therefore breaks nobody; adding a scheme to every existing
    alternative, or deleting an alternative, breaks the callers who relied on
    it.
    """
    if not old:
        return (bool(new), "operation now requires auth where it required none"
                if new else "")
    if not new:
        return False, ""
    stranded = [alt for alt in old
                if not any(candidate <= alt for candidate in new)]
    if not stranded:
        return False, ""
    lost = " OR ".join("+".join(sorted(alt)) for alt in stranded)
    return True, (f"callers authenticating with `{lost}` can no longer "
                  f"satisfy this operation")


def _diff_operation(old: Operation, new: Operation) -> List[Finding]:
    out: List[Finding] = []
    out.extend(_diff_params(old, new))
    # Only the shallow, inline part of a body is compared here; anything named
    # is handled exactly by the schema diff.
    out.extend(_diff_fields(old.request_fields, new.request_fields, new, "request"))

    if not old.request_required and new.request_required:
        out.append(_mk(
            new, "request_body_now_required", BREAKING,
            "request body became required",
            subject="<body>", old="optional", new="required",
        ))

    new_success = {s for s in new.responses if s.startswith("2")}
    for status, old_resp in old.responses.items():
        new_resp = new.responses.get(status)
        if new_resp is None:
            if status.startswith("2"):
                # Removing one success status while others remain NARROWS what
                # the server can return. A client already handling the survivor
                # is unaffected; only one that branched exclusively on the
                # removed code notices, and the spec cannot show that. Discord
                # dropped 204 from bulk-ban while keeping 200, and scoring that
                # as breaking produced ten leads against libraries that never
                # read the status at all.
                remaining = sorted(new_success)
                if remaining:
                    out.append(_mk(
                        new, "response_status_removed", POTENTIALLY_BREAKING,
                        f"success response `{status}` was removed; "
                        f"{', '.join(remaining)} remain, so only a client "
                        f"branching on `{status}` alone is affected",
                        subject=status, old=status, new="<removed>",
                    ))
                else:
                    out.append(_mk(
                        new, "response_status_removed", BREAKING,
                        f"success response `{status}` was removed and no "
                        f"success status remains",
                        subject=status, old=status, new="<removed>",
                    ))
            continue
        # Shallow only (MAX_DEPTH=2). Named schemas are handled exactly by the
        # schema diff, and `collapse()` merges the two views because both reduce
        # to the same root cause. What this still covers is an INLINE response
        # body, which has no named schema for the other pass to find.
        out.extend(_diff_fields(old_resp, new_resp, new, "response", status))

    tightened, why = _security_tightened(old.security, new.security)
    if tightened:
        out.append(_mk(
            new, "security_requirement_added", BREAKING, why,
            subject="<security>",
            old=_render_security(old.security),
            new=_render_security(new.security),
        ))

    if not old.deprecated and new.deprecated:
        out.append(_mk(
            new, "endpoint_deprecated", POTENTIALLY_BREAKING,
            "operation was marked deprecated",
            subject="<operation>", old="active", new="deprecated",
        ))
    return out


_PATH_PARAM = re.compile(r"\{[^}]*\}")


def caller_visible_path(op_key: str) -> str:
    """An operation key as a CALLER sees it, with parameter NAMES erased.

    A path parameter's name is OpenAPI-internal, exactly like a schema name.
    `/v2/Conversations/{Sid}` and `/v2/Conversations/{id}` produce byte-
    identical URLs for every concrete value, so renaming one moves nothing.

    `dependence.paths_match()` has always normalised this away when matching a
    caller's literal against a template -- the engine knew parameter names did
    not matter while it was PROVING, and did not know it while it was DIFFING.
    Twilio renamed `{Sid}` to `{id}` across Conversations and ControlPlane and
    that produced 15 of 79 breaking findings, none of which breaks anybody.
    """
    method, _, path = op_key.partition(" ")
    # A query string is not part of the path. OpenAI publishes
    # `/responses?beta=true` as a path key alongside `/responses`; the endpoint
    # is the same one and the flag is a parameter, so counting it as a NEW
    # endpoint told six callers they had gained something they already had.
    path = path.partition("?")[0]
    return f"{method} {_PATH_PARAM.sub('{}', path)}"


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


# --------------------------------------------------------------------------
# additions
#
# The breaking surface is small and the additive surface is not. Measured over
# the same 90-day window across the five vendors here: 64 breaking changes,
# against 112 new operations and 332 new optional fields. A tool that only
# fires on breakage fires almost never for any given repository -- 22 real
# repositories were scanned against those 64 changes and none was affected.
#
# These are not findings. Nothing here is wrong with anyone's code. The claim
# is weaker and different: this vendor now offers something, and this repo is
# positioned to use it.
# --------------------------------------------------------------------------

OPPORTUNITY = "opportunity"

ADDITIVE_KINDS = frozenset({
    "endpoint_added", "schema_field_added", "param_added_optional",
    "response_field_added", "spec_added",
})

ADDITIVE_LABEL = {
    "spec_added": "new API version",
    "endpoint_added": "new endpoint",
    "schema_field_added": "new optional field",
    "param_added_optional": "new optional parameter",
    "response_field_added": "new field in a response",
}


def _resource_of(path: str) -> str:
    """The first static segment of a path, which is the resource it belongs to.

    `/v1/subscriptions/{id}/cancel` and `/v1/subscriptions` are the same
    resource; `/v1/charges` is not. This is what makes a NEW endpoint relevant
    to a repo that has never called it: they already work with this resource.
    """
    for segment in path.split("/"):
        if not segment or "{" in segment:
            continue
        low = segment.lower()
        if low in {"api", "2010-04-01"} or re.fullmatch(r"v\d+", low):
            continue
        return segment
    return ""


def spec_added_finding(path: str, spec: "Spec") -> Finding:
    """A spec FILE that did not exist before.

    Silently skipping these as "purely additive" is a false negative on the
    single most consequential event a sharded vendor produces. Adyen ships 129
    per-service, per-version files and a new API version arrives as a NEW FILE
    -- `CheckoutService-v52.json` -- so a differ watching v51 path-by-path
    reports "no change" forever and misses the launch entirely.

    It is an opportunity, not a break: nothing was taken away.
    """
    op_keys = sorted(spec.operations)
    first = spec.operations[op_keys[0]] if op_keys else None
    carrier = first or Operation(path="/", method="get", operation_id=None,
                                 summary="", deprecated=False)
    finding = _mk(
        carrier, "spec_added", OPPORTUNITY,
        f"`{path}` is new since the last release, with "
        f"{len(op_keys)} operation{'' if len(op_keys) == 1 else 's'}",
        subject=path, old="<absent>", new=path,
    )
    finding.root_cause = path
    finding.blurb = (f"A spec file that did not exist before. For a vendor that "
                     f"ships one file per service version, this is how a new "
                     f"API version arrives.")
    finding.resource = _resource_of(carrier.path)
    finding.affected_ops = op_keys[:200]
    finding.affected_op_count = len(op_keys)
    finding.spec_file = path
    return finding


def _diff_additions(old: Spec, new: Spec) -> List[Finding]:
    """What a caller could newly use, with enough context to judge relevance."""
    out: List[Finding] = []

    old_visible = {caller_visible_path(k) for k in old.operations}
    for key in sorted(set(new.operations) - set(old.operations)):
        if caller_visible_path(key) in old_visible:
            continue          # a renamed parameter, not a new endpoint
        op = new.operations[key]
        finding = _mk(
            op, "endpoint_added", OPPORTUNITY,
            f"`{key}` is new since the last release",
            subject=op.path, old="<absent>", new=key,
        )
        finding.root_cause = op.path
        finding.blurb = op.summary
        finding.resource = _resource_of(op.path)
        # Sibling operations on the same resource are what a repo already
        # calling this resource would be found by.
        finding.affected_ops = sorted(
            k for k in new.operations
            if _resource_of(k.partition(" ")[2]) == finding.resource
            and k != key
        )[:200]
        finding.affected_op_count = len(finding.affected_ops)
        out.append(finding)

    for name in sorted(set(old.schemas) & set(new.schemas)):
        before, after = old.schemas[name], new.schemas[name]
        gained = sorted(set(after.fields) - set(before.fields))
        if not gained:
            continue
        ops = new.reachable.get(name, []) or old.reachable.get(name, [])
        if not ops:
            continue          # nothing a caller touches; not an opportunity
        in_request = new.used_in_requests(name)
        in_response = new.used_in_responses(name)
        carrier = _schema_op(name)
        carrier.path = ops[0].partition(" ")[2] or carrier.path
        carrier.method = (ops[0].partition(" ")[0] or "get").lower()
        for field_name in gained:
            if after.fields[field_name].required:
                continue      # a newly REQUIRED field is a break, reported there
            kind = "schema_field_added" if in_request else "response_field_added"
            finding = _mk(
                carrier, kind, OPPORTUNITY,
                f"`{name}.{field_name}` is new and optional",
                subject=f"{name}.{field_name}",
                old="<absent>", new=after.fields[field_name].signature(),
            )
            finding.root_cause = f"{name}.{field_name}"
            finding.blurb = after.fields[field_name].description
            finding.in_request = bool(in_request)
            finding.in_response = bool(in_response)
            finding.resource = _resource_of(carrier.path)
            finding.affected_ops = ops[:200]
            finding.affected_op_count = len(ops)
            out.append(finding)

    return out


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
            # A renamed operation still has to be compared body-to-body.
            # Skipping it meant a vendor who renamed a path parameter AND
            # dropped a required field in the same release had the field
            # removal go unreported entirely.
            findings.extend(_diff_operation(op, new_op))
            if caller_visible_path(key) == caller_visible_path(new_op.key):
                continue      # a parameter was renamed; the URL is unchanged
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

    findings.extend(_diff_schema_views(old, new, result.suppressed))

    result.additions = _diff_additions(old, new)

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


# The same edit is seen twice: once as a schema definition change and once as
# an inline body change on a route that reaches it. They are one finding.
_KIND_CLASS = {
    "schema_field_removed": "field_removed",
    "response_field_removed": "field_removed",
    "request_field_removed": "field_removed",
    "schema_field_type_changed": "field_type_changed",
    "response_field_type_changed": "field_type_changed",
    "request_field_type_changed": "field_type_changed",
    "schema_field_now_required": "field_now_required",
    "request_field_now_required": "field_now_required",
    "schema_field_added_required": "field_added_required",
    "request_field_added_required": "field_added_required",
    "schema_enum_value_removed": "enum_value_removed",
    "request_enum_value_removed": "enum_value_removed",
    "response_enum_value_removed": "enum_value_removed",
    "schema_enum_value_added": "enum_value_added",
    "response_enum_value_added": "enum_value_added",
    "schema_field_now_nullable": "field_now_nullable",
    "response_field_now_nullable": "field_now_nullable",
}

# When two views of one change merge, the schema view is the authoritative one:
# its reachability comes from a graph walk rather than from one route.
_SCHEMA_KINDS = frozenset(k for k in _KIND_CLASS if k.startswith("schema_"))


def _kind_class(kind: str) -> str:
    return _KIND_CLASS.get(kind, kind)


def collapse(findings: List[Finding], max_ops: int = 200) -> List[Finding]:
    """Group findings that share one root cause into a single finding.

    A shared schema in a large spec fans one edit out across hundreds of
    operations. Reporting each one separately is how an alerting product gets
    muted; the fan-out count is the useful signal, not the repetition.
    """
    groups: Dict[Tuple[str, str, str, str], List[Finding]] = {}
    order: List[Tuple[str, str, str, str]] = []
    for finding in findings:
        key = (_kind_class(finding.kind), root_cause_key(finding.subject),
               "", "")
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append(finding)

    collapsed: List[Finding] = []
    for key in order:
        members = groups[key]
        # Keep the shortest path as representative: it is the most direct route
        # to the changed schema and reads best in a report.
        # Prefer the schema view: its op list is a graph walk, not one route.
        rep = min(members, key=lambda f: (f.kind not in _SCHEMA_KINDS,
                                          len(f.subject), f.op_key))
        rep.occurrences = max(len(members), rep.occurrences)
        rep.root_cause = key[1]
        # `occurrences` counts distinct paths through the spec that reach this
        # change; several of them can land on the same operation. Reporting the
        # occurrence count as an operation count produced "853 operations" for
        # a spec containing 589, which is wrong on its face.
        distinct_ops = {m.op_key for m in members if not _is_pseudo_op(m.op_key)}
        for member in members:
            distinct_ops.update(k for k in (member.affected_ops or ())
                                if not _is_pseudo_op(k))
        # Never shrink a count that reachability already established.
        rep.affected_op_count = max(len(distinct_ops), rep.affected_op_count)
        rep.direct_op_count = max((m.direct_op_count for m in members), default=0)
        rep.affected_ops = sorted(distinct_ops)[:max_ops]
        # Use the authoritative count, not the length of the list, which is
        # capped for output size. Reporting the capped length here contradicted
        # the same number printed in the report header.
        if rep.direct_op_count > 1:
            rep.detail = (f"{rep.detail} — appears directly in "
                          f"{rep.direct_op_count} operations")
        elif rep.affected_op_count > 1:
            rep.detail = f"{rep.detail} — affects {rep.affected_op_count} operations"
        elif len(members) > 1:
            rep.detail = (f"{rep.detail} — reached {len(members)} ways through "
                          f"1 operation")
        collapsed.append(rep)
    return collapsed


# ---------------------------------------------------------------------------
# Schema-level diffing
#
# This replaces deep response-path expansion, which could not be made reliable:
# on Stripe ~45% of the tree is truncated at any depth, and the two sides
# truncate at different points, so most "removed field" findings were really
# "we stopped looking here but not there". A named schema has one definition,
# so comparing definitions is exact.
# ---------------------------------------------------------------------------

def _schema_op(name: str) -> Operation:
    """A carrier so schema findings reuse the Finding shape."""
    return Operation(path=f"#/components/schemas/{name}", method="get",
                     operation_id=name, summary="", deprecated=False)


def _field_shape(field: Field, spec: Spec) -> Optional[Tuple]:
    """What a consumer sees for this field, regardless of how it is written.

    A named schema and an inline definition of the same thing are the same
    thing. Twilio extracted its enums into named schemas without touching a
    value, which read as a type change on twelve fields.
    """
    if field.type.startswith("->"):
        view = spec.schemas.get(field.type[2:])
        if view is None:
            return None
        if view.fields:
            return ("object", tuple(sorted(view.fields)))
        if view.enum:
            return ("enum", view.enum)
        if view.kind == "array":
            # Resolved on both sides or not at all. Answering "array" here
            # while the inline form answered None made the same array compare
            # unequal to itself purely on notation.
            return ("array", view.item) if view.item else None
        return ("scalar", view.kind)
    if field.enum:
        return ("enum", field.enum)
    if field.shape:
        return ("object", field.shape)
    if field.type == "array":
        return ("array", field.item) if field.item else None
    if field.type in ("object", "any", "oneOf", "anyOf"):
        # Too coarse to call equivalent without more resolution.
        return None
    return ("scalar", field.type)


def _same_shape(was: Field, now: Field, old: Spec, new: Spec) -> bool:
    """True when the two notations describe the same thing.

    Covers a schema rename (Plaid renamed
    `CraCheckReportCashflowInsightsGetOptions` to
    `CraCheckReportCreateCashflowInsightsOptions` without altering a field) and
    extraction of an inline definition into a named one, in either direction.
    """
    before = _field_shape(was, old)
    after = _field_shape(now, new)
    return before is not None and before == after


_TYPE_ANNOTATION = re.compile(r"<[^>]*>")


def _operation_field_names(spec: Spec) -> Dict[str, Set[str]]:
    """Every field NAME a consumer can see on each operation, either direction.

    A schema is an implementation detail of an operation; a caller only ever
    sees the operation. Diffing schemas in isolation therefore cannot tell a
    field being DELETED from a field being MOVED between two schemas that
    compose into the same operation -- and the second breaks nobody.

    OpenAI removed `ResponseProperties.reasoning` in this window while
    `POST /responses` went on accepting `reasoning` throughout, because the
    field moved to another arm of the same `allOf`. Every caller passing
    `reasoning=` was reported as broken. Names, not paths, because that is
    what a caller writes and what `dependence.prove()` matches on.
    """
    out: Dict[str, Set[str]] = {}
    for key, op in spec.operations.items():
        names: Set[str] = set()
        for fields in [op.request_fields] + list(op.responses.values()):
            for path in fields:
                names.add(_TYPE_ANNOTATION.sub("", path).rsplit(".", 1)[-1])
        out[key] = names
    return out


def _field_survived_where_it_was_visible(
    field_name: str, ops: Sequence[str],
    old_names: Dict[str, Set[str]], new_names: Dict[str, Set[str]],
) -> bool:
    """True when removing this field changed nothing any caller can observe.

    Requires that the field was actually visible somewhere -- a schema no
    operation reaches tells us nothing -- and that it is still visible on
    every operation where it used to be.
    """
    seen_anywhere = False
    for op_key in ops:
        was, now = old_names.get(op_key), new_names.get(op_key)
        if was is None or now is None or field_name not in was:
            continue
        seen_anywhere = True
        if field_name not in now:
            return False
    return seen_anywhere



def _is_pseudo_op(op_key: str) -> bool:
    """`GET #/components/schemas/X` is a carrier, not an operation.

    `_schema_op` mints one so schema findings can reuse the Finding shape. It
    was then being counted as an affected operation, which is why a schema
    reachable from ZERO operations still reported `affected_op_count: 1` and
    named an operation that exists in no spec. A count of affected operations
    has to be able to reach zero, or it can never say "this affects nobody".
    """
    return "#/components/schemas/" in op_key


def _truncated_ops(spec: Spec) -> Set[str]:
    """Operations whose flattened fields hit the depth cap.

    Anything past `MAX_DEPTH` is invisible on that side, so "the name is still
    there" cannot be established for these. The suppressors below abstain
    instead of guessing, and the abstention is counted rather than silent --
    the standing complaint about the relocation suppressor is that it goes
    quiet exactly where it is least sure.
    """
    out: Set[str] = set()
    for key, op in spec.operations.items():
        for fields in [op.request_fields] + list(op.responses.values()):
            if any(f.type == TRUNCATED for f in fields.values()):
                out.add(key)
                break
    return out


def _incoming_refs(spec: Spec) -> Dict[str, Set[str]]:
    """schema name -> the named schemas that reference it directly."""
    out: Dict[str, Set[str]] = {}
    for name, view in spec.schemas.items():
        for ref in view.refs:
            out.setdefault(ref, set()).add(name)
    return out


def _schema_leaf_names(view: "SchemaView") -> Set[str]:
    """The field names this schema contributes to whatever carries it."""
    return {_TYPE_ANNOTATION.sub("", f).rsplit(".", 1)[-1] for f in view.fields}


def _shape_at_parents(name: str, parents: Set[str],
                      old: Spec, new: Spec) -> bool:
    """Does every surviving parent still present the same shape where it
    pointed at `name`?

    This is the question a caller can answer and the schema table cannot.
    Klaviyo stopped naming its single-value enums: `InTheLastEnum` became
    `{"type": "string", "enum": ["in-the-last"]}` inline at the identical
    property. `_field_shape` already knows a named schema and an inline
    definition of the same thing are the same thing -- it was just never asked
    about the schema that disappeared.
    """
    for parent in parents:
        before, after = old.schemas.get(parent), new.schemas.get(parent)
        if before is None or after is None:
            return False
        for field_name, field in before.fields.items():
            if field.type != f"->{name}":
                continue
            replacement = after.fields.get(field_name)
            if replacement is None:
                return False
            if _field_shape(field, old) != _field_shape(replacement, new):
                return False
    return True


def _view_shape(view, spec: Spec) -> Tuple:
    """What a caller sees of a named schema, one level deep and name-free.

    Deliberately excludes the schema's own NAME: that is the whole point. Two
    schemas with the same kind, the same fields carrying the same shapes, the
    same enum and the same required set are the same thing on the wire no
    matter what the spec author calls them.
    """
    return (view.kind, view.enum, tuple(sorted(view.required)),
            tuple((f, _field_shape(field, spec))
                  for f, field in sorted(view.fields.items())))


def _renamed_at_roots(name: str, view, direct: Sequence[str],
                      old: Spec, new: Spec,
                      new_roots: Dict[str, Set[str]]) -> bool:
    """Did every operation that named this schema simply start naming another
    schema of the identical shape?

    Cloudflare renamed its response envelopes in bulk --
    `aaa_components-schemas-api-response-common-failure` became
    `aaa_api-response-common-failure-3` at the same operation with the same
    `{errors, messages, success}` body. 191 of Cloudflare's removals are that
    and nothing else. A schema rename is invisible on the wire for exactly the
    reason a path-parameter rename is (7a61f0d): the name never travels.

    Anything that genuinely changed inside the body is still reported, by the
    operation-level diff, against the operation. This suppresses the duplicate
    claim, not the change.
    """
    if not direct:
        return False
    want = _view_shape(view, old)
    for op_key in direct:
        candidates = new_roots.get(op_key) or set()
        if not any(_view_shape(new.schemas[c], new) == want
                   for c in candidates if c in new.schemas):
            return False
    return True


def _invert_rooted_at(spec: Spec) -> Dict[str, Set[str]]:
    """operation -> the schemas it names directly."""
    out: Dict[str, Set[str]] = {}
    for schema_name, ops in spec.rooted_at.items():
        for op_key in ops:
            out.setdefault(op_key, set()).add(schema_name)
    return out


def _removal_is_observable(
    name: str, view, ops: Sequence[str], removed: Set[str],
    incoming: Dict[str, Set[str]], old: Spec, new: Spec,
    old_names: Dict[str, Set[str]], new_names: Dict[str, Set[str]],
    truncated: Set[str], reachability_has_signal: bool = True,
    new_roots: Optional[Dict[str, Set[str]]] = None,
) -> Tuple[bool, str]:
    """Can any caller tell that this schema is gone?

    A schema NAME never travels on the wire -- the same fact that made a field
    moving between schemas a non-event (f650b2f) and a path-parameter rename a
    non-event (7a61f0d). It was never applied to the schema ITSELF, and that is
    the largest defect this engine has had: 694 of 1007 `schema_removed`
    findings across 21 vendors describe nothing a caller can observe.

    Three ways a removal is invisible, each decided by a different question:

    unreachable  no operation reaches it, so no request or response could ever
                 have carried it. Sentry publishes a DEREFERENCED spec, whose
                 `components/schemas` table is vestigial: 25 of 25.
    relocated    every place that pointed at it still presents the same shape.
                 Klaviyo stopped naming single-value enum schemas and inlined
                 them at the identical property; the bytes are identical.
    subsumed     no operation names it directly and every schema that does was
                 removed in the same change, each reported on its own. PayPal's
                 `error_409` lived only inside `error_default`. One restructure
                 is one finding, not ninety-two.

    Returns `(observable, reason_when_not)`.
    """
    if not ops:
        # CONTROL, and it is not optional. On a DEREFERENCED document nothing
        # references anything: every schema looks unreachable, so the test is
        # satisfied by 100% of inputs and measures nothing. Sentry publishes
        # `openapi-derefed.json`, and suppressing on this would have silently
        # deleted a real break -- `DetailedOrganizationSerializerWithProjects
        # AndTeams` is verbatim the 200 body of a PUT that still exists and
        # lost seven required response properties. An empty measurement is a
        # claim about the instrument until something says otherwise.
        if not reachability_has_signal:
            return True, "unreachable_unmeasurable"
        return False, "unreachable"

    parents = incoming.get(name) or set()
    direct = set(old.rooted_at.get(name, []))

    # Reached only through other schemas, all of which went in the same
    # change. Nothing can observe this removal except through one of those,
    # and each of those is judged on its own terms.
    if parents and not direct and parents <= removed:
        return False, "subsumed"

    live_parents = parents - removed
    if live_parents and _shape_at_parents(name, live_parents, old, new):
        if not direct:
            return False, "relocated"

    if direct:
        # An operation names it directly: what a caller sees is that
        # operation's own surface, so ask whether any name it contributed
        # stopped being visible there.
        contributed = _schema_leaf_names(view)
        # An operation that no longer exists cannot show anything either way,
        # and its disappearance is already reported as `endpoint_removed`.
        # Judge on the ones a caller can still reach.
        carrying = [op for op in direct if op in new_names]
        if not carrying:
            return False, "subsumed"
        if _renamed_at_roots(name, view, carrying, old, new, new_roots or {}):
            return False, "renamed"
        # This branch, and only this branch, reads the flattened field names.
        # Past `MAX_DEPTH` a name is invisible on that side, so "it is still
        # there" cannot be established: abstain, and let the caller count the
        # abstention. A suppressor that goes quiet exactly where it is least
        # sure is how the relocation blind spot stayed open. The shape test
        # above needs none of this -- it compares schemas, not flattenings.
        if any(op in truncated for op in carrying):
            return True, "truncated"
        if contributed and all(
                not (contributed - (new_names.get(op) or set()))
                for op in carrying
                if contributed & (old_names.get(op) or set())):
            return False, "relocated"
        if not contributed and all(
                not ((old_names.get(op) or set()) - (new_names.get(op) or set()))
                for op in carrying):
            return False, "relocated"

    return True, ""


def _diff_schema_views(old: Spec, new: Spec,
                       suppressed: Optional[Dict[str, int]] = None) -> List[Finding]:
    out: List[Finding] = []
    old_op_names = _operation_field_names(old)
    new_op_names = _operation_field_names(new)
    counts = suppressed if suppressed is not None else {}

    removed_names = set(old.schemas) - set(new.schemas)
    incoming = _incoming_refs(old)
    old_truncated = _truncated_ops(old)
    new_roots = _invert_rooted_at(new)
    # The control for the unreachable test: does this document link schemas at
    # all? If nothing anywhere is reachable, "unreachable" is a property of
    # the document's style, not of the schema.
    reachability_has_signal = bool(old.reachable)

    for name in sorted(removed_names):
        view = old.schemas[name]
        ops = old.reachable.get(name, [])
        observable, reason = _removal_is_observable(
            name, view, ops, removed_names, incoming, old, new,
            old_op_names, new_op_names, old_truncated, reachability_has_signal,
            new_roots,
        )
        if not observable:
            counts[reason] = counts.get(reason, 0) + 1
            continue
        if reason:
            # Reported, but the suppressors could not judge it. Counted so an
            # abstention is never mistaken for a decision.
            counts[reason] = counts.get(reason, 0) + 1
        op = _schema_op(name)
        if ops:
            op.path = ops[0].partition(" ")[2] or op.path
            op.method = (ops[0].partition(" ")[0] or "get").lower()
        finding = _mk(
            op, "schema_removed", BREAKING,
            f"schema `{name}` was removed from the spec",
            subject=name, old=f"{len(view.fields)} fields", new="<removed>",
        )
        finding.root_cause = name
        finding.leaf_fields = sorted(view.fields)
        finding.affected_ops = ops[:200]
        finding.affected_op_count = len(ops)
        finding.direct_op_count = len(old.nearby.get(name, []))
        finding.occurrences = len(ops) or 1
        out.append(finding)

    for name in sorted(set(old.schemas) & set(new.schemas)):
        before, after = old.schemas[name], new.schemas[name]
        ops = new.reachable.get(name, []) or old.reachable.get(name, [])
        # Severity depends on which direction the schema travels. Tightening
        # what a caller must SEND breaks them; tightening what they RECEIVE
        # does not. Stripe's request bodies are inline form schemas, so every
        # named schema there is response-side, and scoring "now required" as
        # breaking across all of them would be wrong 36 times over.
        near = new.nearby.get(name, []) or old.nearby.get(name, [])
        in_request = new.used_in_requests(name) or old.used_in_requests(name)
        in_response = new.used_in_responses(name) or old.used_in_responses(name)
        carrier = _schema_op(name)
        if ops:
            carrier.path = ops[0].partition(" ")[2] or carrier.path
            carrier.method = (ops[0].partition(" ")[0] or "get").lower()

        def emit(kind: str, severity: str, detail: str, subject: str,
                 old_value: str, new_value: str) -> None:
            finding = _mk(carrier, kind, severity, detail, subject=subject,
                          old=old_value, new=new_value)
            finding.root_cause = subject
            finding.in_request = bool(in_request)
            finding.in_response = bool(in_response)
            finding.affected_ops = ops[:200]
            finding.affected_op_count = len(ops)
            finding.direct_op_count = len(near)
            finding.occurrences = len(ops) or 1
            out.append(finding)

        for field_name, was in before.fields.items():
            now = after.fields.get(field_name)
            subject = f"{name}.{field_name}"
            if now is None:
                if _field_survived_where_it_was_visible(
                        field_name, ops, old_op_names, new_op_names):
                    continue      # moved between schemas, not taken away
                # Losing a field a caller READS breaks them. Losing one they
                # merely send is usually ignored by the server.
                emit("schema_field_removed",
                     BREAKING if in_response else POTENTIALLY_BREAKING,
                     f"`{subject}` was removed from the schema",
                     subject, was.signature(), "<removed>")
                continue
            if was.type != now.type and not _same_shape(was, now, old, new):
                was_shape = _field_shape(was, old)
                now_shape = _field_shape(now, new)
                if (was_shape and now_shape
                        and was_shape[0] == "enum" == now_shape[0]):
                    # Both sides are enums, so the change is in the VALUES.
                    # Report it as such: widening a response enum is a
                    # fall-through risk, not a type break.
                    dropped = sorted(set(was_shape[1]) - set(now_shape[1]))
                    gained = sorted(set(now_shape[1]) - set(was_shape[1]))
                    if dropped:
                        emit("schema_enum_value_removed",
                             BREAKING if in_request else POTENTIALLY_BREAKING,
                             f"`{subject}` no longer allows: {', '.join(dropped)}",
                             subject, "|".join(was_shape[1]), "|".join(now_shape[1]))
                    if gained and in_response:
                        emit("schema_enum_value_added", POTENTIALLY_BREAKING,
                             f"`{subject}` gained values: {', '.join(gained)} "
                             f"(exhaustive switches will fall through)",
                             subject, "|".join(was_shape[1]), "|".join(now_shape[1]))
                else:
                    emit("schema_field_type_changed", BREAKING,
                         f"`{subject}` changed type", subject, was.type, now.type)
            if not was.required and now.required and in_request:
                emit("schema_field_now_required", BREAKING,
                     f"`{subject}` became required in a request schema",
                     subject, "optional", "required")
            if was.enum and now.enum:
                dropped = sorted(set(was.enum) - set(now.enum))
                added = sorted(set(now.enum) - set(was.enum))
                if dropped:
                    # Unsendable if it is a request value; merely unexpected if
                    # it is one you used to receive.
                    emit("schema_enum_value_removed",
                         BREAKING if in_request else POTENTIALLY_BREAKING,
                         f"`{subject}` no longer allows: {', '.join(dropped)}",
                         subject, "|".join(was.enum), "|".join(now.enum))
                if added and in_response:
                    emit("schema_enum_value_added", POTENTIALLY_BREAKING,
                         f"`{subject}` gained values: {', '.join(added)} "
                         f"(exhaustive switches will fall through)",
                         subject, "|".join(was.enum), "|".join(now.enum))
            if not was.nullable and now.nullable:
                emit("schema_field_now_nullable", POTENTIALLY_BREAKING,
                     f"`{subject}` became nullable", subject, "non-null", "nullable")

        for field_name, now in after.fields.items():
            if field_name in before.fields:
                continue
            if now.required and in_request:
                subject = f"{name}.{field_name}"
                emit("schema_field_added_required", BREAKING,
                     f"request schema `{name}` gained required field "
                     f"`{field_name}`",
                     subject, "<absent>", now.signature())
    return out
