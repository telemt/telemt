#!/usr/bin/env python3
"""Generate/check the versioned Control API route and envelope artifact.

The operation catalog is also consumed by /v1/capabilities. Existing response
payloads remain intentionally unconstrained; API.md defines their detailed DTOs.
"""
import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CATALOG = ROOT / "src/api/discovery/operations.json"
OUTPUT = ROOT / "docs/Architecture/API/openapi-v1.json"


def ref(name):
    return {"$ref": f"#/components/schemas/{name}"}


def object_schema(properties, required=(), extra=False):
    return {"type": "object", "properties": properties,
            "required": list(required), "additionalProperties": extra}


def nullable(schema):
    return {"anyOf": [schema, {"type": "null"}]}


def build_document():
    operations = json.loads(CATALOG.read_text())
    string = {"type": "string"}
    boolean = {"type": "boolean"}
    count = {"type": "integer", "minimum": 0}
    secret = {"type": "string", "pattern": "^[0-9A-Fa-f]{32}$"}
    username = {"type": "string", "pattern": "^[A-Za-z0-9_.-]{1,64}$"}
    user_properties = {
        "secret": nullable(secret), "user_ad_tag": nullable(secret),
        "max_tcp_conns": nullable(count),
        "expiration_rfc3339": nullable({"type": "string", "format": "date-time"}),
        "data_quota_bytes": nullable(count),
        "quota_period": nullable({"enum": ["daily", "weekly", "monthly"]}),
        "rate_limit_up_bps": nullable(count), "rate_limit_down_bps": nullable(count),
        "max_unique_ips": nullable(count), "enabled": nullable(boolean),
        "source_deny": nullable({"type": "array", "items": {"type": "string", "format": "cidr"}}),
    }
    schemas = {
        "SuccessEnvelope": object_schema({"ok": {"const": True}, "data": {},
                                          "revision": string}, ("ok", "data", "revision")),
        "ErrorEnvelope": object_schema({
            "ok": {"const": False}, "request_id": count,
            "error": object_schema({"code": string, "message": string,
                                    "details": {"type": "array", "items": ref("FieldIssue")}}, ("code", "message")),
        }, ("ok", "error", "request_id")),
        "CreateUserRequest": object_schema({"username": username, **user_properties},
                                            ("username",), extra=True),
        "PatchUserRequest": object_schema(user_properties, extra=True),
        "RotateSecretRequest": object_schema({"secret": nullable(secret)}, extra=True),
        "PatchConfigRequest": object_schema({
            **{k: nullable({"type": "object"}) for k in
               ("general", "timeouts", "censorship", "dc_overrides", "web")},
            "upstreams": nullable({"type": "array", "items": {"type": "object"}}),
            "server": nullable(object_schema({
                "listeners": nullable({"type": "array", "items": {"type": "object"}}),
                "api": nullable(object_schema({
                    "minimal_runtime_enabled": nullable(boolean),
                    "minimal_runtime_cache_ttl_ms": nullable({"type": "integer", "minimum": 0, "maximum": 60000}),
                    "runtime_edge_enabled": nullable(boolean),
                    "runtime_edge_cache_ttl_ms": nullable({"type": "integer", "minimum": 0, "maximum": 60000}),
                    "runtime_edge_top_n": nullable({"type": "integer", "minimum": 1, "maximum": 1000}),
                })),
            })),
            "network": nullable(object_schema({"dns_overrides": nullable({"type": "array", "items": string, "maxItems": 4096})})),
        }),
        "ReloadRequest": object_schema({
            "mode": {"enum": ["instant", "drain"], "default": "instant"},
            "timeout_secs": nullable({"type": "integer", "minimum": 1, "maximum": 3600}),
            "failure_policy": {"enum": ["keep_new", "rollback"], "default": "keep_new"},
        }),
        "RuntimeInstanceRequest": object_schema({"runtime_instance": string}, ("runtime_instance",)),
        "DrainRequest": object_schema({"runtime_instance": string,
                                       "timeout_secs": {"type": "integer", "minimum": 1, "maximum": 3600}},
                                      ("runtime_instance", "timeout_secs")),
        "CloseRequest": object_schema({"runtime_instance": string, "selector": {"type": "object"}},
                                      ("runtime_instance", "selector")),
    }
    operation_properties = {
        "id": string, "method": {"enum": ["GET", "POST", "PATCH", "DELETE"]},
        "path": string, "aliases": {"type": "array", "items": string},
        "gate": {"enum": ["always", "minimal", "minimal_me", "middle_proxy", "upstream", "edge", "web_read", "web_control"]},
        "success": {"type": "array", "items": {"type": "integer"}},
        "credential_bearing": boolean, "body": string, "optional_body": boolean,
        "exact_json_content_type": boolean, "if_match": boolean,
        "if_runtime_match": boolean, "read_only_operation": boolean,
        "supported": boolean, "enabled": boolean, "available": nullable(boolean), "mutable": boolean,
        "disabled_reason": string, "unavailable_reason": string, "mutation_blocked_reason": string,
    }
    schemas["OperationCapability"] = object_schema(operation_properties,
        ("id", "method", "path", "gate", "success", "credential_bearing", "optional_body",
         "exact_json_content_type", "if_match", "if_runtime_match", "read_only_operation",
         "supported", "enabled", "available", "mutable"))
    schemas["CapabilitiesData"] = object_schema({
        "api_version": {"const": "v1"}, "schema_version": {"const": 1}, "software_version": string,
        "config_schema": {"const": "/v1/config/schema"}, "openapi_artifact": string,
        "read_only": boolean, "availability_scope": string,
        "operations": {"type": "array", "items": ref("OperationCapability")},
    }, ("api_version", "schema_version", "software_version", "config_schema", "openapi_artifact",
        "read_only", "availability_scope", "operations"))
    schemas["FieldApi"] = object_schema({
        "config_read": boolean, "config_write": boolean,
        "read_routes": {"type": "array", "items": string}, "write_routes": {"type": "array", "items": string},
        "request_field": string, "non_editable_reason": string, "null_behavior": string,
    }, ("config_read", "config_write", "read_routes", "write_routes", "null_behavior"))
    schemas["FieldMetadata"] = object_schema({
        "path": string, "value": {"type": "object"}, "default": {},
        "default_kind": {"enum": ["type_default", "unset", "required", "nested_fields", "map_entry", "redacted"]},
        "sensitivity": {"enum": ["public", "deployment", "credential"]}, "description": string,
        "aliases": {"type": "array", "items": string}, "unit": string,
        "apply": object_schema({"watcher": string, "reload": string, "effect": string},
                               ("watcher", "reload", "effect")),
        "dependencies": {"type": "array", "items": string},
        "constraints": {"type": "array", "items": string}, "api": ref("FieldApi"),
    }, ("path", "value", "default_kind", "sensitivity", "description", "apply", "api"))
    schemas["ConfigSchemaData"] = object_schema({
        "schema_version": {"const": 1}, "value_schema_dialect": string,
        "defaults_scope": string, "validation_scope": string, "path_notation": string,
        "config_patch": object_schema({k: string for k in
            ("objects", "arrays", "object_null_members", "reset", "source_ownership", "if_match")},
            ("objects", "arrays", "object_null_members", "reset", "source_ownership", "if_match")),
        "fields": {"type": "array", "items": ref("FieldMetadata")},
    }, ("schema_version", "value_schema_dialect", "defaults_scope", "validation_scope", "path_notation", "config_patch", "fields"))
    for name in ("Capabilities", "ConfigSchema"):
        schemas[name + "Response"] = object_schema({
            "ok": {"const": True}, "data": ref(name + "Data"), "revision": string,
        }, ("ok", "data", "revision"))
    strings = {"type": "array", "items": string}
    schemas["FieldIssue"] = object_schema({"path": string, "code": string, "message": string},
                                          ("path", "code", "message"))
    schemas["NormalizationEffect"] = object_schema({"path": string,
        "code": {"enum": ["normalized", "null_ignored", "alias_canonicalized"]}}, ("path", "code"))
    schemas["RuntimeBaseline"] = object_schema({"active_generation": count, "config_epoch": count,
        "runtime_match": string}, ("active_generation", "config_epoch", "runtime_match"))
    rates = object_schema({"up_bps": {**count, "maximum": 100000000000},
                           "down_bps": {**count, "maximum": 100000000000}})
    policy = {"user_max_tcp_conns_global_each": count, "user_max_unique_ips_global_each": count,
              "user_max_unique_ips_mode": {"enum": ["active_window", "time_window", "combined"]},
              "user_max_unique_ips_window_secs": {"type": "integer", "minimum": 1},
              "cidr_rate_limits": {"type": "object", "additionalProperties": rates}}
    schemas["AccessPolicy"] = object_schema(policy, policy.keys())
    schemas["AccessPolicyPatch"] = {**object_schema({key: nullable(value) for key, value in policy.items()}),
        "minProperties": 1, "description": "Omitted fields stay unchanged. Scalar null restores the type default. cidr_rate_limits null clears the map; otherwise keys merge, null entries delete, and non-null entries replace the whole rate pair in bits/second. At least one direction must be positive. One writable source per mutation."}
    schemas["AccessPolicyPatch"]["properties"]["cidr_rate_limits"] = nullable({"type": "object", "additionalProperties": nullable(rates)})
    policy_state = {"desired": ref("AccessPolicy"), "effective": ref("AccessPolicy"),
        "runtime": ref("RuntimeBaseline"), "published_match": boolean,
        "effective_scope": {"const": "active_config_snapshot"}, "subsystem_convergence": {"const": "unknown"},
        "apply_mode": {"const": "watcher"}, "changed_paths": strings}
    schemas["AccessPolicyData"] = object_schema(policy_state, [key for key in policy_state if key != "changed_paths"])
    schemas["AccessPolicyResponse"] = object_schema({"ok": {"const": True}, "data": ref("AccessPolicyData"),
        "revision": string}, ("ok", "data", "revision"))
    impact = {**{k: strings for k in ("watcher_paths", "generation_paths", "process_restart_paths", "deferred_process_fields")},
              **{k: boolean for k in ("restart_required", "runtime_reload_required", "process_restart_required")}}
    schemas["ApplyImpact"] = object_schema(impact, impact.keys())
    validation = {"valid": {"const": True}, "base_revision": string, "candidate_revision": string,
        "runtime": ref("RuntimeBaseline"), "changed_paths": strings,
        "normalization_effects": {"type": "array", "items": ref("NormalizationEffect")},
        "apply": ref("ApplyImpact"), "source_ownership": {"const": "single_source"},
        "touched_sections": strings, "reload": nullable(ref("ReloadRequest")),
        "warnings": {"type": "array", "items": ref("FieldIssue")}}
    schemas["ConfigValidationData"] = object_schema(validation, validation.keys())
    schemas["ConfigValidationResponse"] = object_schema({"ok": {"const": True},
        "data": ref("ConfigValidationData"), "revision": string}, ("ok", "data", "revision"))
    sections = ["general", "network", "server", "timeouts", "censorship", "upstreams",
                "dc_overrides", "web", "access", "logging", "root"]
    field_projection = {
        "path": {"type": "string", "maxLength": 256}, "value": {}, "redacted": boolean,
        "present": boolean, "entries": nullable(count), "differs": nullable(boolean),
        "origin": {"enum": ["source", "type_default", "default_or_derived", "inherited",
                             "runtime_derived", "mixed_unknown", "unknown"]},
        "inherited_from": {"const": "network.prefer"},
    }
    schemas["ConfigFieldProjection"] = object_schema(field_projection,
        ("path", "redacted", "present", "entries", "differs", "origin"))
    projection = {
        "fields": {"type": "array", "items": ref("ConfigFieldProjection"), "maxItems": 1024},
        "truncated": boolean,
        "provenance": {"enum": ["normalized_source", "mixed_publication", "unknown"]},
        "source_revision": nullable(string), "source_count": nullable(count),
    }
    schemas["ConfigProjection"] = object_schema(projection, projection.keys())
    comparison = {
        "scope": {"const": "selected_sections"},
        "status": {"enum": ["unknown", "published_match", "pending_publication", "process_deferred"]},
        **{key: {**strings, "maxItems": 512} for key in ("pending_paths", "watcher_pending_paths",
            "generation_pending_paths", "process_deferred_paths")},
        "deferred_process_fields": strings, "runtime_derived_paths": strings, "truncated": boolean,
    }
    schemas["ConfigStateComparison"] = object_schema(comparison, comparison.keys())
    watcher = {
        "sequence": count, "observed_at_epoch_secs": count,
        "phase": {"enum": ["initial", "preparing", "unchanged", "retained", "published",
                            "published_partial", "source_refreshed", "rejected", "publication_failed"]},
        "source_revision": nullable(string), "published_config_epoch": nullable(count),
        "error_code": nullable(string),
    }
    schemas["ConfigWatcherObservation"] = object_schema(watcher, watcher.keys())
    reload_observation = {
        "reload_id": count, "target_generation": count, "source_revision": string,
        "phase": {"enum": ["accepted", "preparing", "activating", "draining", "succeeded", "rolled_back", "failed"]},
        **{key: nullable(count) for key in ("source_generation", "activated_generation",
                                          "retiring_generation", "retiring_config_epoch")},
        "retirement": nullable({"enum": ["retiring", "draining", "retired", "cleanup_timeout"]}),
        "error_present": boolean, "warning_count": count,
    }
    schemas["ConfigReloadObservation"] = object_schema(reload_observation, reload_observation.keys())
    state = {
        "scope": {"const": "published_configuration_not_subsystem_acknowledgment"},
        "sections": {"type": "array", "items": {"enum": sections}, "uniqueItems": True,
                     "minItems": 1, "maxItems": len(sections)},
        "runtime": ref("RuntimeBaseline"), "runtime_sample_current": boolean,
        "desired_revision": nullable(string),
        "desired_status": {"enum": ["valid", "invalid", "unreadable", "timeout", "busy", "unavailable"]},
        "desired_error": nullable(ref("FieldIssue")), "projection_error": nullable(ref("FieldIssue")),
        "desired": nullable(ref("ConfigProjection")), "effective": nullable(ref("ConfigProjection")),
        "comparison": ref("ConfigStateComparison"),
        "watcher": nullable(ref("ConfigWatcherObservation")), "watcher_matches_desired": nullable(boolean),
        "reload": nullable(ref("ConfigReloadObservation")), "reload_matches_desired": nullable(boolean),
        "reload_observation": {"enum": ["sampled", "busy", "unknown"]},
        "subsystem_convergence": {"const": "unknown"},
    }
    schemas["ConfigStateData"] = object_schema(state, state.keys())
    schemas["ConfigStateResponse"] = object_schema({"ok": {"const": True},
        "data": ref("ConfigStateData"), "revision": nullable(string)}, ("ok", "data", "revision"))
    schemas["PatchConfigRequest"]["description"] = "Sparse merge; object null members are ignored. Unknown nested and inapplicable variant fields are rejected before deserialization. Validate complete candidates on the server. Field metadata: GET /v1/config/schema."
    schemas["ReloadRequest"]["description"] = "drain requires timeout_secs; instant forbids a non-null timeout_secs."
    paths = {}
    for operation in operations:
        for path in [operation["path"], *operation.get("aliases", [])]:
            alias = path != operation["path"]
            parameters = []
            for segment in path.split('/'):
                if segment.startswith('{'):
                    parameters.append({"name": segment[1:-1], "in": "path", "required": True,
                                       "schema": {"type": "integer", "minimum": 0} if segment == '{id}' else string})
            if operation.get("if_match"):
                parameters.append({"name": "If-Match", "in": "header", "required": False,
                                   "schema": string, "description": "Quoted or unquoted source-manifest revision."})
            if operation.get("if_runtime_match"):
                parameters.append({"name": "If-Runtime-Match", "in": "header", "required": False,
                                   "schema": string, "description": "Optional opaque publication token returned by config/validate or config/state; stale runtime assumptions return 409 runtime_conflict."})
            if operation["id"] in ("config_patch", "config_validate"):
                parameters.extend({"name": name, "in": "query", "schema": schema} for name, schema in (
                    ("reload", {"enum": ["instant", "drain"]}),
                    ("timeout_secs", {"type": "integer", "minimum": 1, "maximum": 3600}),
                    ("failure_policy", {"enum": ["keep_new", "rollback"]}),
                ))
            if operation["id"] == "config_state":
                parameters.append({"name": "sections", "in": "query", "style": "form", "explode": False,
                    "schema": {"type": "array", "items": {"enum": sections}, "uniqueItems": True,
                               "minItems": 1, "maxItems": len(sections)},
                    "description": "Comma-separated sections; omitted selects all. One parameter only, at most 256 query bytes. Snapshots are independently sampled; comparison is not a convergence acknowledgment."})
            response_schema = {"capabilities": "CapabilitiesResponse", "config_schema": "ConfigSchemaResponse",
                               "config_validate": "ConfigValidationResponse",
                               "access_policy_get": "AccessPolicyResponse", "access_policy_patch": "AccessPolicyResponse",
                               "config_state": "ConfigStateResponse"}.get(operation["id"], "SuccessEnvelope")
            responses = {str(status): {"description": "Success or documented state payload",
                         "content": {"application/json": {"schema": ref(response_schema)}}}
                         for status in operation["success"]}
            responses["default"] = {"description": "Structured API error; whitelist gray actions may instead drop or return empty HTTP 200.",
                                    "content": {"application/json": {"schema": ref("ErrorEnvelope")}}}
            if path == '/web-status':
                responses = {"200": {"description": "Authenticated HTML diagnostics", "content": {"text/html": {"schema": string}}},
                             "default": {"description": "API admission errors are JSON; renderer/query errors may be HTML."}}
            entry = {"operationId": operation["id"] + ("_alias" if alias else ""),
                     "responses": responses, "x-telemt-gate": operation["gate"],
                     "x-telemt-credential-bearing": operation.get("credential_bearing", False)}
            if operation.get("read_only_operation"):
                entry["x-telemt-read-only-operation"] = True
                entry["description"] = "Authenticated preflight permitted under read_only. Reads DNS/static assets without persistence, publication, reload reservation or listener binding. Two concurrent preparations, 30 second deadline; cancelled workers retain their slot until exit. Apply classifications describe a publication baseline, not subsystem convergence or guaranteed startup."
                for status, description in {"409": "Source, runtime or source-ownership conflict.",
                                            "429": "Both preparation slots are occupied.",
                                            "504": "Preparation exceeded 30 seconds."}.items():
                    responses[status] = {"description": description, "content": {"application/json": {"schema": ref("ErrorEnvelope")}}}
            if parameters:entry['parameters'] = parameters
            if operation.get('body'):
                entry['requestBody'] = {"required": not operation.get('optional_body', False),
                                        "content": {"application/json": {"schema": ref(operation['body'])}}}
                entry['x-telemt-exact-json-content-type'] = operation.get('exact_json_content_type', False)
            paths.setdefault(path, {})[operation['method'].lower()] = entry
    return {"openapi": "3.1.0", "info": {"title": "Telemt Control API", "version": "v1-discovery-1",
            "description": "Generated by tools/generate_api_openapi.py. Routes and envelopes are checked against the runtime catalog. Legacy data payload details, query filters and cross-field constraints remain in API.md. Discovery is administrative, not an observer authorization role."},
            "security": [{}, {"AuthorizationHeader": []}],
            "paths": paths, "components": {"securitySchemes": {"AuthorizationHeader": {
                "type": "apiKey", "in": "header", "name": "Authorization",
                "description": "Exact configured header value, required only when header authentication is enabled; direct-peer whitelist applies independently."}},
                "schemas": schemas}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    rendered = json.dumps(build_document(), indent=2, ensure_ascii=False) + "\n"
    if args.check:
        if not OUTPUT.is_file() or OUTPUT.read_text() != rendered:
            parser.exit(1, f"Outdated artifact: run {Path(__file__).name}\n")
        print("OpenAPI artifact matches the operation catalog")
    else:
        OUTPUT.write_text(rendered)
        print(OUTPUT.relative_to(ROOT))


if __name__ == "__main__":
    main()
