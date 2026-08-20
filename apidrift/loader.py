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
MAX_DEPTH = 6


class SpecParseError(Exception):
    pass


@dataclass(frozen=True)
class Field:
    """One leaf or branch in a flattened schema."""
    type: str
    required: bool
    nullable: bool
    enum: Optional[Tuple[str, ...]] = None

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
    security: Tuple[str, ...] = ()

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
    if depth > MAX_DEPTH or schema is None:
        return out
    # A response/body that is a bare `$ref` still belongs to a named schema.
    # Seeding the prefix with that name lets one edit to a shared schema group
    # with the same edit reached through a union arm.
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
            rs, _ = resolver.resolve(schema, seen)
            if isinstance(rs, dict):
                stype = _type_of(rs)
                enum = _enum_of(rs)
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


def _security_names(node: Any) -> Tuple[str, ...]:
    if not isinstance(node, list):
        return ()
    names: List[str] = []
    for req in node:
        if isinstance(req, dict):
            names.extend(sorted(req.keys()))
    return tuple(sorted(set(names)))


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

    return Spec(
        version=version,
        title=title,
        servers=tuple(servers),
        operations=operations,
        security_schemes=security_schemes,
    )
