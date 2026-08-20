"""Parse an OpenAPI document and normalize it into comparable operation records.

The goal is not to be a spec-complete OpenAPI parser. It is to reduce two
versions of a spec to a shape where a *semantic* diff is a set comparison
rather than a text diff.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

import yaml

HTTP_METHODS = ("get", "put", "post", "delete", "options", "head", "patch", "trace")

# Depth cap for $ref expansion. Real specs (Stripe) have schemas that nest far
# deeper than any consumer meaningfully depends on, and expanding them fully is
# quadratic. 6 covers `data[].object.nested.field` style access.
MAX_DEPTH = 2

# Marker type for a subtree the flattener stopped short of. It has to be
# recorded rather than silently dropped: if one version nests one level deeper
# than the other, everything past the cap on the deeper side simply vanishes,
# and a diff reads that absence as deletion. That single asymmetry produced
# most of Stripe's "removed response field" findings.
TRUNCATED = "__truncated__"


class SpecParseError(Exception):
    pass


@dataclass(frozen=True)
class Field:
    """One leaf or branch in a flattened schema."""
    type: str
    required: bool
    nullable: bool
    enum: Optional[Tuple[str, ...]] = None
    # Property names when this field is an inline object. Without them an
    # inline definition cannot be compared against a named one describing the
    # same thing, and extracting a schema reads as a type change.
    shape: Optional[Tuple[str, ...]] = None
    # For an array field, what its elements are. "array" alone is too coarse to
    # compare -- it makes an array-of-string look like an array-of-object.
    item: Optional[str] = None
    # The vendor's own sentence about what this field is for. Never compared:
    # a reworded description is an edit to prose, not to the API. It exists so
    # a SUGGESTION can say what the thing does instead of only naming it --
    # `PaymentInitiationPaymentCreateRequest.user_id` is a string; "the ID of
    # the user to associate with the payment" is advice.
    description: str = ""

    def signature(self) -> str:
        parts = [self.type]
        if self.enum:
            parts.append("enum(" + "|".join(self.enum) + ")")
        if self.nullable:
            parts.append("nullable")
        return " ".join(parts)


@dataclass(frozen=True)
class Param:
    name: str
    location: str  # path | query | header | cookie
    required: bool
    type: str
    enum: Optional[Tuple[str, ...]] = None
    deprecated: bool = False

    @property
    def key(self) -> Tuple[str, str]:
        return (self.location, self.name)


@dataclass
class Operation:
    path: str
    method: str
    operation_id: Optional[str]
    summary: str
    deprecated: bool
    params: Dict[Tuple[str, str], Param] = field(default_factory=dict)
    request_fields: Dict[str, Field] = field(default_factory=dict)
    request_required: bool = False
    responses: Dict[str, Dict[str, Field]] = field(default_factory=dict)
    # One frozenset per ALTERNATIVE, each holding the schemes that must be
    # satisfied together: `[{A}, {B}]` is "A or B". The annotation said
    # `Tuple[str, ...]` until 2026-08-20 — a fossil of the flattened model that
    # scored nine Twilio operations as breaking when an alternative was ADDED.
    # `_security_names` has returned `Tuple[frozenset, ...]` since that fix, so
    # the annotation described a shape the loader never produces, and anyone
    # reading the dataclass re-learned the misconception the fix removed.
    security: Tuple[frozenset, ...] = ()

    @property
    def key(self) -> str:
        return f"{self.method.upper()} {self.path}"


@dataclass
class Spec:
    version: str
    title: str
    servers: Tuple[str, ...]
    operations: Dict[str, Operation]
    security_schemes: Dict[str, str]
    schemas: Dict[str, "SchemaView"] = field(default_factory=dict)
    reachable: Dict[str, List[str]] = field(default_factory=dict)
    # schema name -> operations that reference it DIRECTLY from a requestBody,
    # a parameter or a response. Distinct from `reachable`, which is the whole
    # transitive walk: a schema can be reachable only through other schemas,
    # and then removing it is not separately observable.
    rooted_at: Dict[str, List[str]] = field(default_factory=dict)
    # Reachable within two hops: what a consumer would actually see in the
    # payload. Full transitive reachability on a hyperconnected spec says
    # "589 of 589 operations", which is true and useless.
    nearby: Dict[str, List[str]] = field(default_factory=dict)
    request_schemas: frozenset = frozenset()
    response_schemas: frozenset = frozenset()

    def used_in_requests(self, name: str) -> bool:
        return name in self.request_schemas

    def used_in_responses(self, name: str) -> bool:
        return name in self.response_schemas

    @property
    def op_count(self) -> int:
        return len(self.operations)


def parse_document(raw: bytes, filename: str) -> Dict[str, Any]:
    text = raw.decode("utf-8", errors="replace")
    if filename.endswith(".json"):
        try:
            return json.loads(text)
        except json.JSONDecodeError as exc:
            raise SpecParseError(f"{filename}: invalid JSON: {exc}") from exc
    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise SpecParseError(f"{filename}: invalid YAML: {exc}") from exc
    if not isinstance(doc, dict):
        raise SpecParseError(f"{filename}: top level is {type(doc).__name__}, expected mapping")
    return doc


class Resolver:
    """Resolves local `#/...` JSON pointers with cycle protection."""

    def __init__(self, root: Dict[str, Any]):
        self.root = root

    def resolve(self, node: Any, seen: Optional[Set[str]] = None) -> Tuple[Any, Set[str]]:
        seen = set(seen or ())
        hops = 0
        while isinstance(node, dict) and "$ref" in node:
            ref = node["$ref"]
            if not isinstance(ref, str) or not ref.startswith("#/"):
                # External refs are not fetched; treat as opaque.
                return {"type": "external"}, seen
            if ref in seen:
                return {"type": "__cycle__", "__ref__": ref}, seen
            seen.add(ref)
            hops += 1
            if hops > 32:
                return {"type": "__cycle__", "__ref__": ref}, seen
            target: Any = self.root
            for token in ref[2:].split("/"):
                token = token.replace("~1", "/").replace("~0", "~")
                if not isinstance(target, dict) or token not in target:
                    return {"type": "__missing__", "__ref__": ref}, seen
                target = target[token]
            node = target
        return node, seen


def _type_of(schema: Dict[str, Any]) -> str:
    t = schema.get("type")
    if isinstance(t, list):  # OpenAPI 3.1 allows type arrays
        non_null = [x for x in t if x != "null"]
        return non_null[0] if non_null else "null"
    if t:
        return str(t)
    if "properties" in schema:
        return "object"
    if "items" in schema:
        return "array"
    for comb in ("oneOf", "anyOf"):
        if comb in schema:
            return comb
    if "allOf" in schema:
        return "object"
    return "any"


def _is_nullable(schema: Dict[str, Any]) -> bool:
    if schema.get("nullable") is True:
        return True
    t = schema.get("type")
    return isinstance(t, list) and "null" in t


def _enum_of(schema: Dict[str, Any]) -> Optional[Tuple[str, ...]]:
    enum = schema.get("enum")
    if not isinstance(enum, list) or not enum:
        return None
    return tuple(sorted(str(v) for v in enum))


def _merge_all_of(schema: Dict[str, Any], resolver: Resolver, seen: Set[str]) -> Dict[str, Any]:
    """Collapse allOf into a single object schema (properties + required union)."""
    merged: Dict[str, Any] = {k: v for k, v in schema.items() if k != "allOf"}
    props: Dict[str, Any] = dict(merged.get("properties") or {})
    required: List[str] = list(merged.get("required") or [])
    for member in schema.get("allOf") or []:
        resolved, seen2 = resolver.resolve(member, seen)
        if not isinstance(resolved, dict):
            continue
        if "allOf" in resolved:
            resolved = _merge_all_of(resolved, resolver, seen2)
        props.update(resolved.get("properties") or {})
        required.extend(resolved.get("required") or [])
        if "type" not in merged and resolved.get("type"):
            merged["type"] = resolved["type"]
    if props:
        merged["properties"] = props
        merged.setdefault("type", "object")
    if required:
        merged["required"] = sorted(set(required))
    return merged



def _slug(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.=-]+", "-", str(text)).strip("-")[:48]


_DISCRIMINANT_PROPS = ("type", "object", "kind", "event", "status", "role")


def _arm_name(member: Any, resolver: "Resolver", seen: Set[str]) -> str:
    """A *content-derived* name for one arm of a oneOf/anyOf.

    Positional indices (`<oneOf[3]>`) are unstable: inserting an arm shifts every
    later arm and makes the whole subtree look removed-and-readded. Naming an arm
    by what it *is* makes the diff order-independent.
    """
    if isinstance(member, dict):
        ref = member.get("$ref")
        if isinstance(ref, str) and "/" in ref:
            return _slug(ref.rsplit("/", 1)[-1])
    resolved, _ = resolver.resolve(member, seen)
    if not isinstance(resolved, dict):
        return "any"
    if resolved.get("title"):
        return _slug(resolved["title"])
    props = resolved.get("properties")
    if isinstance(props, dict):
        for disc in _DISCRIMINANT_PROPS:
            node = props.get(disc)
            if isinstance(node, dict):
                if "const" in node:
                    return _slug(f"{disc}={node['const']}")
                enum = node.get("enum")
                if isinstance(enum, list) and len(enum) == 1:
                    return _slug(f"{disc}={enum[0]}")
        # Order-independent structural fingerprint.
        digest = hashlib.sha1(",".join(sorted(map(str, props))).encode()).hexdigest()
        return "shape-" + digest[:8]
    enum = _enum_of(resolved)
    if enum:
        digest = hashlib.sha1("|".join(enum).encode()).hexdigest()
        return "enum-" + digest[:8]
    return _slug(_type_of(resolved))


def _named_arms(members: List[Any], resolver: "Resolver", seen: Set[str]) -> List[Tuple[str, Any]]:
    """Name every arm, disambiguating genuine collisions deterministically."""
    counts: Dict[str, int] = {}
    out: List[Tuple[str, Any]] = []
    for member in members:
        name = _arm_name(member, resolver, seen)
        counts[name] = counts.get(name, 0) + 1
        out.append((name if counts[name] == 1 else f"{name}~{counts[name]}", member))
    return out


def flatten_schema(
    schema: Any,
    resolver: Resolver,
    prefix: str = "",
    depth: int = 0,
    required: bool = False,
    seen: Optional[Set[str]] = None,
) -> Dict[str, Field]:
    """Flatten a schema into {dotted.field.path: Field}.

    Arrays contribute a `[]` segment so `data[].id` reads the way a consumer
    actually accesses it.
    """
    out: Dict[str, Field] = {}
    if schema is None:
        return out
    if depth > MAX_DEPTH:
        if prefix:
            out[prefix] = Field(type=TRUNCATED, required=required, nullable=False)
        return out
    # A response/body that is a bare `$ref` still belongs to a named schema.
    # Seeding the prefix with that name lets one edit to a shared schema group
    # with the same edit reached through a union arm.
    #
    # Only at the ROOT. Stamping nested `$ref` names too was tried and reverted:
    # it makes a schema *rename* at a stable field position (OpenAI moved
    # `Response.service_tier` from `ServiceTier` to `ServiceTierResponses`) look
    # like the field was deleted, because both names are real and so neither is
    # blinded. That inflated Stripe from 290 breaking changes to 494. Better
    # grouping is not worth inventing removals.
    if not prefix and isinstance(schema, dict) and isinstance(schema.get("$ref"), str):
        ref = schema["$ref"]
        if ref.startswith("#/components/schemas/") or ref.startswith("#/definitions/"):
            prefix = f"<{_slug(ref.rsplit('/', 1)[-1])}>"
    resolved, seen = resolver.resolve(schema, seen)
    if not isinstance(resolved, dict):
        return out
    if "allOf" in resolved:
        resolved = _merge_all_of(resolved, resolver, seen)

    stype = _type_of(resolved)
    nullable = _is_nullable(resolved)
    enum = _enum_of(resolved)

    if prefix:
        out[prefix] = Field(type=stype, required=required, nullable=nullable, enum=enum)

    if stype in ("oneOf", "anyOf"):
        # Record the union arms' field sets so removing an arm is visible, but
        # do not explode the cross product. Arms are keyed by content, not
        # position, so inserting an arm does not rewrite its siblings' paths.
        for name, member in _named_arms(list(resolved.get(stype) or []), resolver, seen):
            child_prefix = f"{prefix}<{name}>" if prefix else f"<{name}>"
            out.update(flatten_schema(member, resolver, child_prefix, depth + 1, False, seen))
        return out

    if stype == "array":
        items = resolved.get("items")
        if items is not None:
            child_prefix = f"{prefix}[]" if prefix else "[]"
            out.update(flatten_schema(items, resolver, child_prefix, depth + 1, False, seen))
        return out

    props = resolved.get("properties")
    if isinstance(props, dict):
        req_names = set(resolved.get("required") or [])
        for name, sub in props.items():
            child_prefix = f"{prefix}.{name}" if prefix else str(name)
            out.update(
                flatten_schema(sub, resolver, child_prefix, depth + 1, name in req_names, seen)
            )
    return out


def _pick_content_schema(content: Any, resolver: Resolver) -> Any:
    """Prefer JSON, then form-encoded, then whatever is first."""
    if not isinstance(content, dict) or not content:
        return None
    for mime in ("application/json", "application/x-www-form-urlencoded", "*/*"):
        if mime in content:
            return (content[mime] or {}).get("schema")
    for mime, body in content.items():
        if "json" in str(mime):
            return (body or {}).get("schema")
    first = next(iter(content.values()))
    return (first or {}).get("schema")


def _collect_params(
    raw_params: Any, resolver: Resolver
) -> Dict[Tuple[str, str], Param]:
    out: Dict[Tuple[str, str], Param] = {}
    if not isinstance(raw_params, list):
        return out
    for entry in raw_params:
        resolved, seen = resolver.resolve(entry, None)
        if not isinstance(resolved, dict):
            continue
        name = resolved.get("name")
        loc = resolved.get("in")
        if not name or not loc:
            continue
        schema = resolved.get("schema")
        stype, enum = "any", None
        if isinstance(schema, dict):
            # `{"allOf": [{"$ref": X}]}` is how a vendor attaches a sibling
            # keyword to a `$ref`, because `$ref` siblings are ignored in
            # OpenAPI 3.0. It is the same X. `_ref_name` has always known that
            # for schema PROPERTIES and the parameter path never learned it,
            # so Cloudflare unwrapping ten of its own sorting enums read as
            # `object -> string` ten times.
            if "allOf" in schema:
                schema = _merge_all_of(schema, resolver, set())
            rs, _ = resolver.resolve(schema, seen)
            if isinstance(rs, dict):
                stype = _type_of(rs)
                enum = _effective_enum(rs, resolver)
        elif resolved.get("type"):  # Swagger 2.0 style
            stype = str(resolved["type"])
            enum = _enum_of(resolved)
        param = Param(
            name=str(name),
            location=str(loc),
            required=bool(resolved.get("required", loc == "path")),
            type=stype,
            enum=enum,
            deprecated=bool(resolved.get("deprecated", False)),
        )
        out[param.key] = param
    return out


def _security_names(node: Any) -> Tuple[frozenset, ...]:
    """Security as OpenAPI defines it: a list of ALTERNATIVES.

    Each entry is one way to authenticate, and the keys within an entry must
    all be satisfied together. So `[{A}, {B}]` means "A or B", and flattening
    it to `{A, B}` loses the distinction between adding an alternative (which
    breaks nobody) and adding a requirement (which breaks everybody). Twilio
    added `access_token_bearer` alongside `accountSid_authToken` on nine
    operations, and the flattened form scored all nine as breaking.
    """
    if not isinstance(node, list):
        return ()
    alternatives: List[frozenset] = []
    for requirement in node:
        if isinstance(requirement, dict):
            alternatives.append(frozenset(str(k) for k in requirement))
    return tuple(alternatives)


def load_spec(raw: bytes, filename: str) -> Spec:
    doc = parse_document(raw, filename)
    resolver = Resolver(doc)

    version = str(doc.get("openapi") or doc.get("swagger") or "unknown")
    info = doc.get("info") if isinstance(doc.get("info"), dict) else {}
    title = str(info.get("title") or filename)

    servers: List[str] = []
    for srv in doc.get("servers") or []:
        if isinstance(srv, dict) and srv.get("url"):
            servers.append(str(srv["url"]))
    if not servers and doc.get("host"):  # Swagger 2.0
        schemes = doc.get("schemes") or ["https"]
        base = doc.get("basePath") or ""
        servers = [f"{schemes[0]}://{doc['host']}{base}"]

    schemes_node = ((doc.get("components") or {}).get("securitySchemes")
                    or doc.get("securityDefinitions") or {})
    security_schemes = {
        str(k): str((v or {}).get("type", "unknown"))
        for k, v in schemes_node.items()
        if isinstance(v, dict)
    }

    root_security = _security_names(doc.get("security"))
    operations: Dict[str, Operation] = {}
    paths = doc.get("paths")
    if not isinstance(paths, dict):
        raise SpecParseError(f"{filename}: no `paths` object")

    for path, item in paths.items():
        resolved_item, _ = resolver.resolve(item, None)
        if not isinstance(resolved_item, dict):
            continue
        shared = _collect_params(resolved_item.get("parameters"), resolver)
        for method in HTTP_METHODS:
            op_node = resolved_item.get(method)
            if not isinstance(op_node, dict):
                continue
            params = dict(shared)
            params.update(_collect_params(op_node.get("parameters"), resolver))

            request_fields: Dict[str, Field] = {}
            request_required = False
            body_node, _ = resolver.resolve(op_node.get("requestBody"), None)
            if isinstance(body_node, dict):
                request_required = bool(body_node.get("required", False))
                schema = _pick_content_schema(body_node.get("content"), resolver)
                request_fields = flatten_schema(schema, resolver)

            responses: Dict[str, Dict[str, Field]] = {}
            for status, resp in (op_node.get("responses") or {}).items():
                resolved_resp, _ = resolver.resolve(resp, None)
                if not isinstance(resolved_resp, dict):
                    continue
                schema = _pick_content_schema(resolved_resp.get("content"), resolver)
                if schema is None and "schema" in resolved_resp:  # Swagger 2.0
                    schema = resolved_resp["schema"]
                responses[str(status)] = flatten_schema(schema, resolver)

            op_sec = op_node.get("security")
            security = _security_names(op_sec) if op_sec is not None else root_security

            op = Operation(
                path=str(path),
                method=method,
                operation_id=op_node.get("operationId"),
                summary=str(op_node.get("summary") or op_node.get("description") or "")[:160],
                deprecated=bool(op_node.get("deprecated", False)),
                params=params,
                request_fields=request_fields,
                request_required=request_required,
                responses=responses,
                security=security,
            )
            operations[op.key] = op

    views = build_schema_views(doc)
    every, request_roots, response_roots = operation_schema_roots(doc)
    return Spec(
        version=version,
        title=title,
        servers=tuple(servers),
        operations=operations,
        security_schemes=security_schemes,
        schemas=views,
        reachable=reachable_operations(views, every),
        rooted_at=_invert_roots(every),
        nearby=reachable_operations(views, every, max_hops=2),
        request_schemas=frozenset(reachable_operations(views, request_roots)),
        response_schemas=frozenset(reachable_operations(views, response_roots)),
    )


# ---------------------------------------------------------------------------
# Schema-level view
#
# Flattening an operation's response into deep dotted paths cannot work on a
# spec whose schema graph is effectively unbounded: measured on Stripe, ~45% of
# the tree is truncated at every depth from 6 to 9, and doubling the cap only
# doubles the cost. Worse, the two sides truncate at different points, so the
# difference between them is dominated by where the walk stopped rather than by
# what the vendor changed.
#
# A named schema, by contrast, has exactly one definition. Comparing those
# definitions one level deep is exact, and reachability -- which operations a
# schema is visible from -- is a graph walk with a visited set, so it is linear
# rather than exponential and needs no cap at all.
# ---------------------------------------------------------------------------

@dataclass
class SchemaView:
    """One named schema, resolved one level deep."""
    name: str
    fields: Dict[str, Field]
    required: Tuple[str, ...]
    refs: Tuple[str, ...]          # schemas this one references, directly
    kind: str                      # object | array | enum | primitive | union
    enum: Optional[Tuple[str, ...]] = None
    item: Optional[str] = None     # for an array: what its elements are


def _ref_name(node: Any) -> Optional[str]:
    """The schema a property points at, seeing through a single-arm `allOf`.

    Vendors wrap `$ref: X` as `allOf: [$ref: X]` when they need to attach a
    sibling keyword such as `deprecated`, because `$ref` siblings are ignored in
    OpenAPI 3.0. The referenced type is unchanged, so reading the wrapper as a
    different type reports a break where none exists. Plaid did this to
    `Transfer.guarantee_decision`.
    """
    if not isinstance(node, dict):
        return None
    ref = node.get("$ref")
    if isinstance(ref, str) and "/" in ref:
        return ref.rsplit("/", 1)[-1]
    arms = node.get("allOf")
    if isinstance(arms, list) and len(arms) == 1 and "properties" not in node:
        return _ref_name(arms[0])
    return None


def _direct_refs(node: Any, depth: int = 0) -> List[str]:
    """Every schema name referenced inside `node`, without following them."""
    out: List[str] = []
    if depth > 8 or not isinstance(node, (dict, list)):
        return out
    if isinstance(node, list):
        for item in node:
            out.extend(_direct_refs(item, depth + 1))
        return out
    name = _ref_name(node)
    if name:
        out.append(name)
        return out
    for value in node.values():
        out.extend(_direct_refs(value, depth + 1))
    return out


def _effective_enum(schema: Dict[str, Any], resolver: "Resolver") -> Optional[Tuple[str, ...]]:
    """The enum a consumer actually sees, through a nullable union wrapper.

    `anyOf: [{enum: [...]}, {type: null}]` is how a nullable enum is written.
    Reading only the top level finds no enum there, so widening the values
    inside looks like no change at all.
    """
    direct = _enum_of(schema)
    if direct:
        return direct
    for key in ("oneOf", "anyOf"):
        arms = schema.get(key)
        if not isinstance(arms, list):
            continue
        meaningful = []
        for arm in arms:
            resolved, _ = resolver.resolve(arm, None)
            if isinstance(resolved, dict) and _type_of(resolved) != "null":
                meaningful.append(resolved)
        if len(meaningful) == 1:
            return _enum_of(meaningful[0])
    return None


def _follow_alias(schema: Dict[str, Any], resolver: "Resolver",
                  budget: int = 6) -> Dict[str, Any]:
    """Resolve a schema whose entire body is a `$ref` to what it points at."""
    while (isinstance(schema, dict) and "$ref" in schema
           and len(schema) == 1 and budget > 0):
        resolved, _ = resolver.resolve(schema, None)
        if not isinstance(resolved, dict) or resolved is schema:
            return schema
        schema, budget = resolved, budget - 1
    return schema


def _item_type(node: Any, resolver: "Resolver") -> Optional[str]:
    """For an array, what its elements are -- `string`, `object`, `->Name`.

    Without this an array is just "array", so an inline `array of string` and a
    named schema holding an `array of string` compared unequal purely on
    notation, while an `array of string` and an `array of object` compared
    equal once both were called coarse. Cloudflare inlined and named the same
    array-of-string in eleven places.
    """
    if not isinstance(node, dict) or _type_of(node) != "array":
        return None
    items = node.get("items")
    if not isinstance(items, dict):
        return None
    target = _ref_name(items)
    if target:
        return f"->{target}"
    resolved, _ = resolver.resolve(items, None)
    return _type_of(resolved if isinstance(resolved, dict) else items)


def build_schema_views(doc: Dict[str, Any]) -> Dict[str, SchemaView]:
    """One entry per named schema, with its own properties resolved one level."""
    raw = ((doc.get("components") or {}).get("schemas")
           or doc.get("definitions") or {})
    if not isinstance(raw, dict):
        return {}
    resolver = Resolver(doc)
    views: Dict[str, SchemaView] = {}

    for name, schema in raw.items():
        if not isinstance(schema, dict):
            continue
        # A schema whose whole body is `{"$ref": ...}` is an ALIAS for its
        # target and describes exactly what the target describes. Left
        # unresolved it came out as kind `any` with no fields, so a caller's
        # field that switched from the alias to the target read as a type
        # change -- Cloudflare's `magic_interconnect_health_check` is
        # `{"$ref": ".../magic_health_check_base"}` in BOTH versions, and the
        # only thing that moved was which of the two names a property spelled.
        schema = _follow_alias(schema, resolver)
        merged = _merge_all_of(schema, resolver, set()) if "allOf" in schema else schema
        stype = _type_of(merged)
        required = tuple(sorted(str(r) for r in (merged.get("required") or [])))
        fields: Dict[str, Field] = {}

        props = merged.get("properties")
        if isinstance(props, dict):
            for prop_name, prop in props.items():
                # One level only: the property's own type, plus the name of the
                # schema it points at. Following it is the graph walk's job.
                target = _ref_name(prop)
                resolved, _ = resolver.resolve(prop, None) if not target else (prop, None)
                node = prop if target else (resolved if isinstance(resolved, dict) else {})
                inline_props = (node.get("properties")
                                if isinstance(node, dict) else None)
                blurb = ""
                for source in (prop, node):
                    if isinstance(source, dict) and source.get("description"):
                        blurb = str(source["description"])
                        break
                fields[str(prop_name)] = Field(
                    type=(f"->{target}" if target else _type_of(node)),
                    item=_item_type(node, resolver) if not target else None,
                    required=str(prop_name) in required,
                    nullable=_is_nullable(node) if isinstance(node, dict) else False,
                    enum=(_effective_enum(node, resolver)
                          if isinstance(node, dict) and not target else None),
                    shape=(tuple(sorted(inline_props))
                           if isinstance(inline_props, dict) else None),
                    description=" ".join(blurb.split())[:400],
                )

        views[str(name)] = SchemaView(
            name=str(name),
            fields=fields,
            required=required,
            refs=tuple(sorted(set(_direct_refs(schema)))),
            kind=stype,
            enum=_effective_enum(merged, resolver),
            item=_item_type(merged, resolver),
        )
    return views


def operation_schema_roots(
    doc: Dict[str, Any],
) -> Tuple[Dict[str, List[str]], Dict[str, List[str]], Dict[str, List[str]]]:
    """op_key -> schema names referenced (all, request-side, response-side).

    The split matters for severity. A field becoming required breaks callers
    only if they have to SEND it; on a response-only schema the caller simply
    receives more. Without provenance every such change is scored as breaking.
    """
    every: Dict[str, List[str]] = {}
    request: Dict[str, List[str]] = {}
    response: Dict[str, List[str]] = {}
    paths = doc.get("paths")
    if not isinstance(paths, dict):
        return every, request, response
    for path, item in paths.items():
        if not isinstance(item, dict):
            continue
        for method in HTTP_METHODS:
            op = item.get(method)
            if not isinstance(op, dict):
                continue
            key = f"{method.upper()} {path}"
            req = set(_direct_refs(op.get("requestBody")))
            req |= set(_direct_refs(op.get("parameters")))
            resp = set(_direct_refs(op.get("responses")))
            if req:
                request[key] = sorted(req)
            if resp:
                response[key] = sorted(resp)
            if req or resp:
                every[key] = sorted(req | resp)
    return every, request, response


def _invert_roots(roots: Dict[str, List[str]]) -> Dict[str, List[str]]:
    """schema name -> the operations naming it directly."""
    out: Dict[str, List[str]] = {}
    for op_key, names in roots.items():
        for name in names:
            out.setdefault(name, []).append(op_key)
    return {k: sorted(v) for k, v in out.items()}


def reachable_operations(
    views: Dict[str, SchemaView], roots: Dict[str, List[str]],
    max_hops: Optional[int] = None,
) -> Dict[str, List[str]]:
    """schema name -> operations from which it is reachable.

    A breadth-first walk per operation, each with its own visited set. That is
    linear in the graph and terminates on cycles, which is exactly what path
    flattening could not do.

    Memoising a per-schema closure was tried and is WRONG here: when the walk
    cuts a cycle it returns a result that depended on the current stack, and
    caching that under the node's name poisons every later lookup. `Card` in a
    Wallet/Card cycle came back reachable from nothing.
    """
    out: Dict[str, set] = {}
    for op_key, names in roots.items():
        seen: set = set()
        queue = [(name, 0) for name in names]
        while queue:
            name, hops = queue.pop()
            if name in seen:
                continue
            seen.add(name)
            if max_hops is not None and hops >= max_hops:
                continue
            view = views.get(name)
            if view:
                queue.extend((ref, hops + 1) for ref in view.refs if ref not in seen)
        for name in seen:
            out.setdefault(name, set()).add(op_key)
    return {k: sorted(v) for k, v in out.items()}
