//! The management API as an OpenAPI 3.1 document.
//!
//! The console is one client of the API and a script is the other, and the
//! second one had nothing to read but the handbook. This is the surface for
//! programs: a client generator, a Terraform provider, an IDE that completes a
//! request — the same document Velstra Cloud serves at the same path, so one
//! tool reads both products.
//!
//! The list here is written by hand, because the router's routes are too: there
//! is no schema behind them the way the cloud console has one. What keeps it
//! honest is [`tests::every_route_the_router_serves_is_documented`], which
//! reads the routes out of `api.rs` and fails when one is missing here or
//! documented here and not served — so the document and the router change in
//! the same commit or the build goes red.
//!
//! Served at `GET /api/v1/openapi.json` beside `/api/v1/health`, without a
//! token: it is documentation, it names no secret, and a client has to read it
//! before it can know how to sign in.

use serde_json::{Map, Value, json};

/// The document, as JSON.
pub fn document() -> Value {
    let mut paths = Map::new();
    for op in OPERATIONS {
        let entry = paths
            .entry(op.path.to_string())
            .or_insert_with(|| json!({}));
        let mut o = json!({
            "summary": op.summary,
            "description": op.description,
            "operationId": op.id,
            "responses": {
                "200": { "description": op.answer },
                "default": {
                    "description": "Refused: `{\"error\": \"<a sentence>\"}` with the status saying why (400 malformed, 401 no or wrong token, 429 locked out, 500 the box could not answer).",
                    "content": { "application/json": { "schema": { "$ref": "#/components/schemas/Error" } } },
                },
            },
        });
        if !op.parameters.is_empty() {
            o["parameters"] = Value::Array(
                op.parameters
                    .iter()
                    .map(|(name, place, what)| {
                        json!({ "name": name, "in": place, "required": *place == "path", "description": what, "schema": { "type": "string" } })
                    })
                    .collect(),
            );
        }
        if let Some((media, body)) = op.body {
            o["requestBody"] =
                json!({ "required": true, "content": { media: { "schema": body() } } });
        }
        if op.open {
            o["security"] = json!([]);
        }
        if let Some((media, schema)) = op.answer_shape {
            o["responses"]["200"]["content"] = json!({ media: { "schema": schema() } });
        }
        entry[op.method] = o;
    }
    json!({
        "openapi": "3.1.0",
        "info": {
            "title": "Velstra Sentinel",
            "version": env!("CARGO_PKG_VERSION"),
            "description": "The appliance's management API: the same service that serves \
                the console. Everything but `health`, `login` and this document sits behind \
                a bearer token — the machine token in `/var/lib/sentinel/api-token`, or the \
                one `login` hands back for an account. The configuration is one document \
                the box reconciles to; `configure` runs a script of `set`/`delete`/`commit` \
                lines exactly as the CLI would, and `config` reads or replaces the whole \
                thing. Nothing here changes the box except `config` (PUT), `configure`, \
                `clear` and `capture`.",
        },
        "servers": [{ "url": "/" }],
        "security": [{ "bearer": [] }],
        "components": {
            "securitySchemes": {
                "bearer": { "type": "http", "scheme": "bearer" }
            },
            "schemas": {
                "Error": {
                    "type": "object",
                    "required": ["error"],
                    "properties": { "error": { "type": "string", "description": "A sentence for a person." } },
                },
                "Trace": {
                    "type": "object",
                    "description": "Where a packet would go and which rule decides it, walked from the configuration.",
                    "required": ["verdict", "decided_by", "steps", "considered", "destination"],
                    "properties": {
                        "verdict": { "type": "string", "enum": ["pass", "drop", "reject", "unfiltered"] },
                        "decided_by": { "type": "string", "description": "A rule name, `default`, `blocklist`, `port-forward`, `block-icmp`, `source validation`, `blackhole route`, `no route`, …" },
                        "ingress_zone": { "type": ["string", "null"] },
                        "egress_interface": { "type": ["string", "null"] },
                        "egress_zone": { "type": ["string", "null"] },
                        "destination": { "type": "string", "description": "After any DNAT." },
                        "steps": { "type": "array", "items": { "type": "object", "required": ["stage", "text"], "properties": { "stage": { "type": "string" }, "text": { "type": "string" } } } },
                        "considered": { "type": "array", "items": { "type": "object", "required": ["rule", "outcome"], "properties": { "rule": { "type": "string" }, "outcome": { "type": "string" } } } },
                    },
                },
            },
        },
        "paths": paths,
    })
}

/// The document, indented, with a trailing newline.
pub fn pretty() -> String {
    let mut text = serde_json::to_string_pretty(&document()).expect("the document is plain data");
    text.push('\n');
    text
}

/// A media type and the schema of what it carries.
type Shape = (&'static str, fn() -> Value);

/// One operation. A struct of literals so the whole surface reads as a table.
struct Operation {
    method: &'static str,
    path: &'static str,
    id: &'static str,
    summary: &'static str,
    description: &'static str,
    /// `(name, "path" | "query", what)`.
    parameters: &'static [(&'static str, &'static str, &'static str)],
    body: Option<Shape>,
    answer: &'static str,
    answer_shape: Option<Shape>,
    /// Reachable without a token.
    open: bool,
}

fn any_object() -> Value {
    json!({ "type": "object", "additionalProperties": true })
}

fn text() -> Value {
    json!({ "type": "string" })
}

fn login_body() -> Value {
    json!({
        "type": "object",
        "required": ["username", "password"],
        "properties": {
            "username": { "type": "string" },
            "password": { "type": "string", "format": "password" },
            "code": { "type": "string", "description": "The second factor, when the account has one." },
        },
    })
}

fn token_answer() -> Value {
    json!({
        "type": "object",
        "properties": {
            "token": { "type": "string", "description": "The account's own token; present it as the bearer from now on." },
            "user": { "type": "string" },
            "permission": { "type": "string", "enum": ["read-only", "read-write"] },
        },
    })
}

fn ha_pair_body() -> Value {
    json!({"type":"object","required":["expected_revision","appliance"],"additionalProperties":false,"properties":{"expected_revision":{"type":"string","pattern":"^[a-f0-9]{64}$"},"appliance":{"type":"object","additionalProperties":true}}})
}

fn capture_body() -> Value {
    json!({
        "type": "object",
        "required": ["interface"],
        "properties": {
            "interface": { "type": "string" },
            "filter": { "type": "string", "description": "A pcap filter, `tcp port 443`." },
            "packets": { "type": "integer", "minimum": 1, "maximum": 500, "default": 50 },
            "seconds": { "type": "integer", "minimum": 1, "maximum": 60, "default": 10 },
        },
    })
}

fn trace_answer() -> Value {
    json!({ "$ref": "#/components/schemas/Trace" })
}

/// Every route `api.rs` serves, in the order the router lists them.
const OPERATIONS: &[Operation] = &[
    Operation {
        method: "get",
        path: "/api/v1/telemetry",
        id: "telemetry",
        summary: "Live dataplane and routing telemetry.",
        description: "Authenticated SSE telemetry events. One collector fans out a bounded 512-packet history with monotonically increasing event IDs, conntrack summary, rule counters, throughput/PPS, HA, routing and WireGuard state. Slow consumers receive the newest snapshot; oldest_event_id exposes gaps. Missing sources appear in errors, never as healthy zeros.",
        parameters: &[],
        body: None,
        answer: "SSE telemetry events, one JSON snapshot per event.",
        answer_shape: Some(("text/event-stream", text)),
        open: false,
    },
    Operation {
        method: "get",
        path: "/api/v1/config/document",
        id: "config-document",
        summary: "Read the complete TOML document.",
        description: "Write access required. Contains secrets; never cache. Returns toml and CAS revision.",
        parameters: &[],
        body: None,
        answer: "The operation result.",
        answer_shape: Some(("application/json", any_object)),
        open: false,
    },
    Operation {
        method: "post",
        path: "/api/v1/config/document",
        id: "apply-document",
        summary: "Validate or provisionally apply TOML.",
        description: "toml, expected_revision and optional validate_only. The default confirmation window is 60 seconds; stale revisions return 409.",
        parameters: &[],
        body: Some(("application/json", any_object)),
        answer: "The operation result.",
        answer_shape: Some(("application/json", any_object)),
        open: false,
    },
    Operation {
        method: "get",
        path: "/api/v1/config/transaction",
        id: "transaction",
        summary: "Read pending configuration confirmation.",
        description: "Returns pending identity, readiness and remaining_seconds, or null. No rollback secrets.",
        parameters: &[],
        body: None,
        answer: "The operation result.",
        answer_shape: Some(("application/json", any_object)),
        open: false,
    },
    Operation {
        method: "post",
        path: "/api/v1/config/confirm",
        id: "confirm-config",
        summary: "Confirm a provisional revision.",
        description: "Body id must match the pending transaction before its monotonic deadline. Expired and stale confirmations return 409.",
        parameters: &[],
        body: Some(("application/json", any_object)),
        answer: "The operation result.",
        answer_shape: Some(("application/json", any_object)),
        open: false,
    },
    Operation {
        method: "post",
        path: "/api/v1/config/revert",
        id: "revert-config",
        summary: "Revert a provisional revision immediately.",
        description: "Body id must match the pending transaction. Restores saved bytes and reconciles the prior working network.",
        parameters: &[],
        body: Some(("application/json", any_object)),
        answer: "The operation result.",
        answer_shape: Some(("application/json", any_object)),
        open: false,
    },
    Operation {
        method: "get",
        path: "/api/v1/ha/proof/{nonce}",
        id: "haProof",
        summary: "Authenticate a peer before sending enrollment credentials.",
        description: "TLS only. HMAC-SHA256 over a fresh 32-byte hexadecimal nonce and the actual served TLS SPKI, with an enrollment-specific domain. A client verifies both the proof and pinned TLS connection before sending a bearer token.",
        parameters: &[(
            "nonce",
            "path",
            "Fresh 32-byte client nonce, encoded as 64 hexadecimal characters.",
        )],
        body: None,
        answer: "Base64 proof; no credential is returned.",
        answer_shape: Some(("application/json", any_object)),
        open: true,
    },
    Operation {
        method: "get",
        path: "/api/v1/ha/enrollment",
        id: "haEnrollment",
        summary: "Read private member facts for authenticated HA enrollment.",
        description: "Requires TLS and the machine credential. Returns the complete canonical appliance and SHA-256 revision with Cache-Control: no-store. Account tokens cannot retrieve this private document.",
        parameters: &[],
        body: None,
        answer: "Private appliance and canonical revision.",
        answer_shape: Some(("application/json", any_object)),
        open: false,
    },
    Operation {
        method: "post",
        path: "/api/v1/ha/pair",
        id: "haPair",
        summary: "Apply an explicit member-adjusted HA pairing revision.",
        description: "Requires TLS and the machine credential. Validates both member profiles and compares expected_revision under the common apply lock. Conflicting edits return 409. Retrying an already saved identical desired revision succeeds without applying twice. The received revision never queues an echo push.",
        parameters: &[],
        body: Some(("application/json", ha_pair_body)),
        answer: "Applied and saved member revision.",
        answer_shape: Some(("application/json", any_object)),
        open: false,
    },
    Operation {
        method: "get",
        path: "/api/v1/health",
        id: "health",
        summary: "Is the API up.",
        description: "The one probe that needs no token: a load balancer or a monitor asks it, and an answer means the service is running — nothing more.",
        parameters: &[],
        body: None,
        answer: "`{\"status\": \"ok\"}`.",
        answer_shape: Some(("application/json", any_object)),
        open: true,
    },
    Operation {
        method: "get",
        path: "/api/v1/openapi.json",
        id: "openapi",
        summary: "This document.",
        description: "OpenAPI 3.1, generated by the binary that serves it.",
        parameters: &[],
        body: None,
        answer: "The document.",
        answer_shape: Some(("application/json", any_object)),
        open: true,
    },
    Operation {
        method: "post",
        path: "/api/v1/login",
        id: "login",
        summary: "Sign in as an account and receive its token.",
        description: "Checks the account's password (and second factor, when it has one) and hands back the token the account holds — the same one an operator could read off the box, so knowing the password grants nothing new, only a way to ask. Throttled per address and per account; a lock-out answers 429 with the seconds remaining.",
        parameters: &[],
        body: Some(("application/json", login_body)),
        answer: "The token and what it may do.",
        answer_shape: Some(("application/json", token_answer)),
        open: true,
    },
    Operation {
        method: "get",
        path: "/api/v1/config",
        id: "get-config",
        summary: "The saved configuration, as JSON, with every secret redacted.",
        description: "Every account that can read the box can reach this, so the config-sync secret, WireGuard private keys, IPsec PSKs, RADIUS and TACACS+ secrets, the SNMP community and password hashes are replaced by a marker before the document leaves the box.",
        parameters: &[],
        body: None,
        answer: "The configuration.",
        answer_shape: Some(("application/json", any_object)),
        open: false,
    },
    Operation {
        method: "put",
        path: "/api/v1/config",
        id: "put-config",
        summary: "Replace the whole configuration.",
        description: "Validate the complete document, then accept a provisional management transaction. An independent worker applies and saves it. Poll config/transaction until ready and POST its id to config/confirm within 60 seconds by default; otherwise the working baseline is restored. Off-box --no-apply emulation saves without changing the network.",
        parameters: &[],
        body: Some(("application/json", any_object)),
        answer: "Accepted provisional transaction; explicit confirmation required on a live appliance.",
        answer_shape: Some(("application/json", any_object)),
        open: false,
    },
    Operation {
        method: "put",
        path: "/api/v1/config-sync",
        id: "put-config-sync",
        summary: "Apply configuration received from an HA peer.",
        description: "The peer's shared policy is validated, applied and saved through the normal commit path. The receiving firewall keeps its hostname, interface addresses, config-sync peers, conntrack-sync endpoint and router ID, so a sync cannot turn the standby into a copy of the sender.",
        parameters: &[],
        body: Some(("application/json", any_object)),
        answer: "What was applied and saved.",
        answer_shape: Some(("application/json", any_object)),
        open: false,
    },
    Operation {
        method: "get",
        path: "/api/v1/status",
        id: "status",
        summary: "Hostname, service states and interfaces.",
        description: "The same facts `sentinel show status` reports.",
        parameters: &[],
        body: None,
        answer: "The status.",
        answer_shape: Some(("application/json", any_object)),
        open: false,
    },
    Operation {
        method: "get",
        path: "/api/v1/show/{path}",
        id: "show",
        summary: "An operational `show`, by path.",
        description: "`/api/v1/show/ip/route` is `show ip route`; the words of the path are the words of the command. The text the CLI prints, as the CLI prints it.",
        parameters: &[(
            "path",
            "path",
            "The show path, `/`-separated: `ip/route`, `firewall/statistics`, `vpn/ipsec/sas`.",
        )],
        body: None,
        answer: "The command's text.",
        answer_shape: Some(("text/plain", text)),
        open: false,
    },
    Operation {
        method: "get",
        path: "/api/v1/rule-hits",
        id: "rule-hits",
        summary: "Which accept rules are carrying traffic, and how much.",
        description: "Attribution over the live flow table against the compiled rules — not a hardware counter. Only accept rules are counted; a drop rule leaves no flow behind.",
        parameters: &[],
        body: None,
        answer: "`{rules: [{name, flows, packets}], flows, answered, counts_only}`.",
        answer_shape: Some(("application/json", any_object)),
        open: false,
    },
    Operation {
        method: "get",
        path: "/api/v1/trace",
        id: "trace",
        summary: "Where would this packet go, and which rule decides it.",
        description: "A walk over the saved configuration in the order the data plane takes it — the arriving link's zone, the blocklist, source validation, a port-forward's rewrite, the route, the rule that wins and the ones passed over, the masquerade on the way out. Nothing is sent; `sentinel trace` prints the same walk.",
        parameters: &[
            ("in", "query", "The link the packet arrives on."),
            (
                "proto",
                "query",
                "`tcp`, `udp`, `icmp`, `icmpv6`, `gre`, `esp`, `ah`, `vrrp`, `ospf`, `pim`.",
            ),
            ("src", "query", "Source address."),
            ("dst", "query", "Destination address, before any NAT."),
            (
                "port",
                "query",
                "Destination port; omit or 0 for a protocol without ports.",
            ),
            (
                "src-mac",
                "query",
                "The sender's hardware address, to consult MAC-group rules.",
            ),
            (
                "icmp-type",
                "query",
                "The ICMP/ICMPv6 type, to consult typed rules.",
            ),
        ],
        body: None,
        answer: "The walk.",
        answer_shape: Some(("application/json", trace_answer)),
        open: false,
    },
    Operation {
        method: "get",
        path: "/api/v1/metrics",
        id: "metrics-list",
        summary: "Which history series are kept, at which resolutions.",
        description: "`series` names what `sentinel-metrics` samples once a minute; `resolutions` says how fine and how far back each level keeps.",
        parameters: &[],
        body: None,
        answer: "`{series: [...], resolutions: [{name, step, keep}]}`.",
        answer_shape: Some(("application/json", any_object)),
        open: false,
    },
    Operation {
        method: "get",
        path: "/api/v1/metrics/{resolution}/{series}",
        id: "metrics-series",
        summary: "One series' samples, already turned into what a chart wants.",
        description: "A counter comes back as a rate per interval and a gauge as its level, so the console and `show history` answer the same question the same way.",
        parameters: &[
            (
                "resolution",
                "path",
                "One of the names `/api/v1/metrics` lists: `minute`, `hour`, `day`.",
            ),
            (
                "series",
                "path",
                "One of the series it lists, `iface.eth0.rx`.",
            ),
        ],
        body: None,
        answer: "The samples.",
        answer_shape: Some(("application/json", any_object)),
        open: false,
    },
    Operation {
        method: "get",
        path: "/metrics",
        id: "prometheus",
        summary: "The live counters in Prometheus text exposition format.",
        description: "A format adapter over the same numbers the JSON endpoints report — per-interface bytes, per-rule hits, sessions — as raw running totals, behind the same bearer token; Prometheus scrapes it with `authorization: credentials_file`.",
        parameters: &[],
        body: None,
        answer: "The exposition.",
        answer_shape: Some(("text/plain", text)),
        open: false,
    },
    Operation {
        method: "post",
        path: "/api/v1/configure",
        id: "configure",
        summary: "Run a configuration script: `set` / `delete` / `commit` lines, as the CLI would.",
        description: "Atomic configuration batch: set, delete, rollback, commit and save only. The whole candidate is validated before mutation; a refused batch returns ok:false and output with no partial application. A live commit returns an accepted provisional transaction requiring explicit confirmation after pending.ready becomes true. At most 256 KiB.",
        parameters: &[],
        body: Some(("text/plain", text)),
        answer: "`{ok, output}` — the CLI's text.",
        answer_shape: Some(("application/json", any_object)),
        open: false,
    },
    Operation {
        method: "post",
        path: "/api/v1/clear/{path}",
        id: "clear",
        summary: "Undo run-time state a detector created.",
        description: "`clear/ids/blocks` lifts every block the intrusion detector placed. Not configuration: it takes effect at once and is nowhere in the saved config, so there is nothing to stage or discard.",
        parameters: &[("path", "path", "What to clear, `ids/blocks`.")],
        body: None,
        answer: "What was cleared.",
        answer_shape: Some(("text/plain", text)),
        open: false,
    },
    Operation {
        method: "post",
        path: "/api/v1/capture",
        id: "capture",
        summary: "See the wire itself, briefly.",
        description: "Headers only, at most 500 packets or 60 seconds, nothing written to disk. A POST although it reads nothing, because it holds a process open for as long as it runs and a GET that does that is one a proxy will repeat.",
        parameters: &[],
        body: Some(("application/json", capture_body)),
        answer: "The capture, as text.",
        answer_shape: Some(("text/plain", text)),
        open: false,
    },
    Operation {
        method: "get",
        path: "/api/v1/lookup/{kind}/{value}",
        id: "lookup",
        summary: "What the appliance can tell you about a value you are typing.",
        description: "Look up the holder of an autonomous system number (`asn`) or the reverse DNS name of an IP address (`ptr`). An unavailable answer returns `known: false`; an unknown kind or malformed value is rejected.",
        parameters: &[
            ("kind", "path", "`asn` or `ptr`."),
            (
                "value",
                "path",
                "An AS number for `asn`, or an IPv4/IPv6 address for `ptr`.",
            ),
        ],
        body: None,
        answer: "`{known, answer}`.",
        answer_shape: Some(("application/json", any_object)),
        open: false,
    },
    Operation {
        method: "get",
        path: "/api/v1/choices/{kind}",
        id: "choices",
        summary: "The values this appliance has for a closed setting.",
        description: "`timezone`, `keyboard` or `locale`: the sets that come from packages on the box rather than from a table in the binary, so a picker cannot go stale in a way the validator has not.",
        parameters: &[("kind", "path", "`timezone`, `keyboard`, `locale`.")],
        body: None,
        answer: "A list.",
        answer_shape: Some(("application/json", any_object)),
        open: false,
    },
    Operation {
        method: "get",
        path: "/api/v1/stack",
        id: "stack",
        summary: "This box and its config-sync peers.",
        description: "The members are the peers `[system.config-sync]` pushes to, reached with the shared secret; nothing is invented to make a second box appear.",
        parameters: &[],
        body: None,
        answer: "The members and whether each answered.",
        answer_shape: Some(("application/json", any_object)),
        open: false,
    },
    Operation {
        method: "get",
        path: "/api/v1/stack/{member}/show/{path}",
        id: "stack-show",
        summary: "An operational `show` on a peer, forwarded over the sync link.",
        description: "A peer's management port is usually not reachable from wherever the operator is, and this box already trusts the link; the request is forwarded already authenticated.",
        parameters: &[
            ("member", "path", "The peer, as `/api/v1/stack` names it."),
            ("path", "path", "The show path."),
        ],
        body: None,
        answer: "The peer's text.",
        answer_shape: Some(("text/plain", text)),
        open: false,
    },
];

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// The router's paths, spelled the way OpenAPI spells them.
    fn served() -> Vec<(String, String)> {
        let src = include_str!("api.rs");
        let mut out = Vec::new();
        for (at, needle) in src.match_indices(".route(") {
            let rest = src[at + needle.len()..].trim_start();
            let Some(rest) = rest.strip_prefix('"') else {
                continue;
            };
            let Some(end) = rest.find('"') else { continue };
            let path = rest[..end]
                .replace("/*path", "/{path}")
                .split('/')
                .map(|seg| match seg.strip_prefix(':') {
                    Some(p) => format!("{{{p}}}"),
                    None => seg.to_string(),
                })
                .collect::<Vec<_>>()
                .join("/");
            // Formatting may spread a route over several lines. Bound the
            // method expression by its balanced outer route call, not a line.
            let mut depth = 1;
            let line_end = rest[end + 1..]
                .char_indices()
                .find_map(|(index, ch)| {
                    match ch {
                        '(' => depth += 1,
                        ')' => depth -= 1,
                        _ => {}
                    }
                    (depth == 0).then_some(end + 1 + index)
                })
                .unwrap_or(rest.len());
            let line = &rest[end..line_end];
            for verb in ["get", "put", "post", "patch", "delete"] {
                if line.contains(&format!("{verb}(")) {
                    out.push((verb.to_string(), path.clone()));
                }
            }
        }
        out
    }

    /// The console and the favicon are pages, not API; everything else the
    /// router serves is in the document, and nothing in the document is
    /// unserved.
    #[test]
    fn every_route_the_router_serves_is_documented() {
        let doc = document();
        let pages = ["/", "/ui", "/favicon.ico"];
        let mut missing = Vec::new();
        for (verb, path) in served() {
            if pages.contains(&path.as_str()) {
                continue;
            }
            if doc["paths"][&path][&verb].is_null() {
                missing.push(format!("{verb} {path}"));
            }
        }
        assert!(missing.is_empty(), "served but not documented: {missing:?}");

        let served: Vec<String> = served()
            .into_iter()
            .map(|(v, p)| format!("{v} {p}"))
            .collect();
        let mut unserved = Vec::new();
        for (path, ops) in doc["paths"].as_object().unwrap() {
            for verb in ops.as_object().unwrap().keys() {
                if !served.contains(&format!("{verb} {path}")) {
                    unserved.push(format!("{verb} {path}"));
                }
            }
        }
        assert!(
            unserved.is_empty(),
            "documented but not served: {unserved:?}"
        );
    }

    #[test]
    fn the_open_routes_are_exactly_the_pre_authentication_surface() {
        let doc = document();
        let mut open = Vec::new();
        for (path, ops) in doc["paths"].as_object().unwrap() {
            for (verb, op) in ops.as_object().unwrap() {
                if op.get("security") == Some(&json!([])) {
                    open.push(format!("{verb} {path}"));
                }
            }
        }
        open.sort();
        assert_eq!(
            open,
            [
                "get /api/v1/ha/proof/{nonce}",
                "get /api/v1/health",
                "get /api/v1/openapi.json",
                "post /api/v1/login"
            ]
        );
    }

    #[test]
    fn the_pretty_form_parses_back() {
        let back: Value = serde_json::from_str(&pretty()).unwrap();
        assert_eq!(back["openapi"], "3.1.0");
        assert_eq!(back["info"]["title"], "Velstra Sentinel");
    }
}
