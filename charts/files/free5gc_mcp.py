#!/usr/bin/env python3
"""free5GC MCP server: the platform's cluster assistant manages this free5GC's subscribers through MCP.

The tools follow github.com/q1317540161/free5gc-MCP (subscriber_* and tenant_users_get, the same arguments and the same
default subscriber), ported to Python and served the way the platform expects an edge app's MCP server:
  - Streamable HTTP (MCP 2025-06-18 / 2025-03-26), JSON-RPC 2.0, POST /mcp, Python standard library + `cryptography`;
  - the tools are exactly those declared in mcp-manifest.json (the platform reads that file from this repository at the
    signed commit it deploys, and stops using the server if what it serves ever differs);
  - only the platform may call it: every request carries X-Platform-Token, signed by the hub's key (ECDSA P-256,
    PLATFORM_KEY = base64 of its PEM, delivered through Fleet), for this namespace ("mcp:ns/<POD_NAMESPACE>"), for the
    SHA-256 of this exact body, unexpired, used once. No key configured: every call is refused (fail closed).
Not ported (lifecycle belongs to the platform, which deploys and upgrades free5GC through Fleet): the shell, systemd,
kubectl and Helm tools (local_free5gc_*, k8s_*).

free5GC side: the WebConsole API (WEBCONSOLE_URL, default http://webui-service:5000), logged in with WEBCONSOLE_USER /
WEBCONSOLE_PASSWORD (a Kubernetes Secret), token in the "Token" header, one re-login on 401/403.

SIM secrets never leave this server: every result has the subscriber keys (permanentKeyValue, opcValue, opValue) replaced
by "[redacted]", so the assistant's model never sees them. A new subscriber gets the keys given in the call, or
free5GC's standard test keys (the ones UERANSIM's example UEs use), as free5gc-MCP does. An unknown SUPI is a tool error
(the WebConsole answers it with HTTP 200 and an empty profile, which would read as "no key"); get, update and patch
never act on one.
"""
import base64
import copy
import hashlib
import json
import os
import re
import threading
import time
import urllib.error
import urllib.request
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MANIFEST = os.environ.get("MANIFEST", os.path.join(os.path.dirname(os.path.abspath(__file__)), "mcp-manifest.json"))
PORT = int(os.environ.get("PORT", "8811"))
VERSIONS = ("2025-06-18", "2025-03-26")
MAX_BODY = 64 * 1024
SESSION_TTL_S = 900
WEBCONSOLE = os.environ.get("WEBCONSOLE_URL", "http://webui-service:5000").rstrip("/")
HTTP_TIMEOUT_S = 15

_sessions = {}
_lock = threading.Lock()
TOKEN_HEADER = "X-Platform-Token"
ISSUER = "platform-hub"
SKEW_S, MAX_TTL_S = 30, 300
_NS = re.compile(r"^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$")
_seen = {}                                  # jti -> exp: each token once
_ID = re.compile(r"^[A-Za-z0-9-]{1,64}$")   # ueId (imsi-…), PLMN id, tenant id: never a path trick
# the WebConsole's names (and, for a later free5GC whose API carries the R17 names or TUAK, those too); matched in any case
SECRET_KEYS = {k.lower() for k in ("permanentKeyValue", "opcValue", "opValue", "topcValue", "topValue",
                                   "encPermanentKey", "encOpcKey", "encTopcKey")}
NO_KEY_WARNING = "this subscriber has no SIM key stored (no permanent key): the UE cannot authenticate until it gets one"
TEST_K, TEST_OPC = "8baf473f2f8fd09487cccbd7097c6862", "8e27b6af0e692e750f32667a3b14605d"


# ── the platform's token (identical to the platform's reference MCP server) ──────────────────────────────────────────
def _b64d(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def own_namespace():
    ns = os.environ.get("POD_NAMESPACE", "").strip()
    return ns if _NS.match(ns) else ""


def expected_audience():
    ns = own_namespace()
    if not ns:
        return None, "the app's namespace is unknown (POD_NAMESPACE): every call is refused"
    return "mcp:ns/" + ns, None


def _platform_key():
    raw = os.environ.get("PLATFORM_KEY", "").strip()
    if not raw:
        return None
    from cryptography.hazmat.primitives import serialization
    return serialization.load_pem_public_key(base64.b64decode(raw))


def check_token(token, body, now=None):
    """None when the platform sent this request, else why not."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    try:
        key = _platform_key()
    except Exception:  # noqa: BLE001
        return "the platform key is not readable"
    if key is None:
        return "no platform key is configured: every call is refused"
    aud, why = expected_audience()
    if why:
        return why
    if not token or token.count(".") != 1:
        return "no platform token"
    now = time.time() if now is None else now
    try:
        payload, sig = (_b64d(p) for p in token.split("."))
        key.verify(sig, payload, ec.ECDSA(hashes.SHA256()))
        c = json.loads(payload)
    except (InvalidSignature, ValueError):
        return "the platform token is not valid"
    if not isinstance(c, dict) or c.get("iss") != ISSUER:
        return "the platform token is not valid"
    if c.get("aud") != aud:
        return "the token is for another app"
    if c.get("body") != hashlib.sha256(body).hexdigest():
        return "the token is for another request"
    iat, exp = c.get("iat"), c.get("exp")
    if not isinstance(iat, int) or not isinstance(exp, int) or exp - iat > MAX_TTL_S or iat > now + SKEW_S \
            or exp < now - SKEW_S:
        return "the token has expired"
    with _lock:
        for j in [j for j, e in _seen.items() if e < now - SKEW_S]:
            _seen.pop(j)
        if c.get("jti") in _seen:
            return "the token was already used"
        _seen[c.get("jti")] = exp
    return None


# ── free5GC WebConsole ────────────────────────────────────────────────────────────────────────────────────────────
class WebConsole:
    def __init__(self, base=WEBCONSOLE):
        self.base, self.token, self.lock = base, None, threading.Lock()

    def _raw(self, method, path, body=None, token=None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.base + path, data=data, method=method)
        req.add_header("Content-Type", "application/json")
        if token:
            req.add_header("Token", token)
        try:
            with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT_S) as r:
                return r.status, r.read()
        except urllib.error.HTTPError as e:
            return e.code, e.read()

    def login(self):
        code, raw = self._raw("POST", "/api/login", {"username": os.environ.get("WEBCONSOLE_USER", "admin"),
                                                    "password": os.environ.get("WEBCONSOLE_PASSWORD", "")})
        if code != 200:
            raise RuntimeError(f"the WebConsole refused the login (HTTP {code})")
        tok = (json.loads(raw or b"{}") or {}).get("access_token")
        if not tok:
            raise RuntimeError("the WebConsole login returned no token")
        with self.lock:
            self.token = tok
        return tok

    def call(self, method, path, body=None):
        """(HTTP status, parsed JSON or text). One re-login when the token is refused."""
        with self.lock:
            tok = self.token
        if not tok:
            tok = self.login()
        code, raw = self._raw(method, path, body, tok)
        if code in (401, 403):
            code, raw = self._raw(method, path, body, self.login())
        try:
            return code, json.loads(raw) if raw else None
        except ValueError:
            return code, raw.decode("utf-8", "replace")[:2000]


WC = WebConsole()


def redact(obj):
    """The subscriber keys replaced by "[redacted]" anywhere in a result (the model never sees a SIM secret)."""
    if isinstance(obj, dict):
        return {k: ("[redacted]" if str(k).lower() in SECRET_KEYS and v not in ("", None) else redact(v))
                for k, v in obj.items()}
    if isinstance(obj, list):
        return [redact(x) for x in obj]
    return obj


def has_key(profile):
    """True when a WebConsole profile carries a SIM permanent key (checked before redaction; the value is never read)."""
    a = profile.get("AuthenticationSubscription") if isinstance(profile, dict) else None
    if not isinstance(a, dict):
        return False
    pk = a.get("permanentKey")
    return (isinstance(pk, dict) and pk.get("permanentKeyValue") not in ("", None)) or \
        a.get("encPermanentKey") not in ("", None)


def stored(ue, plmn):
    """(status, profile) of a subscriber that exists, else ValueError. free5GC's WebConsole answers GET
    /api/subscriber/<ueId>/<plmn> with HTTP 200 and an all-empty profile (permanentKey null) for a SUPI it does not
    know, which reads as a subscriber without keys: a profile with no key is checked against the subscriber list."""
    code, data = WC.call("GET", f"/api/subscriber/{ue}/{plmn}")
    if code >= 400:
        _out(code, data)
    if not has_key(data):
        lc, subs = WC.call("GET", "/api/subscriber")
        if lc >= 400 or not isinstance(subs, list):
            raise ValueError(f"the subscriber list could not be read (HTTP {lc})")
        if not any(isinstance(s, dict) and s.get("ueId") == ue and s.get("plmnID") == plmn for s in subs):
            raise ValueError(f"no subscriber {ue} in PLMN {plmn}")
    return code, data


def default_subscriber(ue_id, plmn, k=TEST_K, opc=TEST_OPC):
    """free5gc-MCP's default subscriber (free5GC's WebConsole defaults: two slices, DNN internet)."""
    s1, s2 = {"sst": 1, "sd": "010203"}, {"sst": 1, "sd": "112233"}
    dnn = lambda q: {"internet": {"pduSessionTypes": {"defaultSessionType": "IPV4", "allowedSessionTypes": ["IPV4"]},
                                  "sscModes": {"defaultSscMode": "SSC_MODE_1", "allowedSscModes": ["SSC_MODE_2", "SSC_MODE_3"]},
                                  "5gQosProfile": {"5qi": q, "priorityLevel": 8,
                                                   "arp": {"priorityLevel": 8, "preemptCap": "", "preemptVuln": ""}},
                                  "sessionAmbr": {"uplink": "1000 Mbps", "downlink": "1000 Mbps"}}}
    return {
        "plmnID": plmn, "ueId": ue_id,
        "AuthenticationSubscription": {
            "authenticationManagementField": "8000", "authenticationMethod": "5G_AKA",
            "milenage": {"op": {"encryptionAlgorithm": 0, "encryptionKey": 0, "opValue": ""}},
            "opc": {"encryptionAlgorithm": 0, "encryptionKey": 0, "opcValue": opc},
            "permanentKey": {"encryptionAlgorithm": 0, "encryptionKey": 0, "permanentKeyValue": k},
            "sequenceNumber": "000000000000"},
        "AccessAndMobilitySubscriptionData": {
            "gpsis": ["msisdn-"], "nssai": {"defaultSingleNssais": [s1], "singleNssais": [s2]},
            "subscribedUeAmbr": {"uplink": "1 Gbps", "downlink": "2 Gbps"}},
        "SessionManagementSubscriptionData": [{"singleNssai": s1, "dnnConfigurations": dnn(9)},
                                              {"singleNssai": s2, "dnnConfigurations": dnn(8)}],
        "SmfSelectionSubscriptionData": {"subscribedSnssaiInfos": {"01010203": {"dnnInfos": [{"dnn": "internet"}]},
                                                                   "01112233": {"dnnInfos": [{"dnn": "internet"}]}}},
        "AmPolicyData": {"subscCats": ["free5gc"]},
        "SmPolicyData": {"smPolicySnssaiData": {
            "01010203": {"snssai": s1, "smPolicyDnnData": {"internet": {"dnn": "internet"}}},
            "01112233": {"snssai": s2, "smPolicyDnnData": {"internet": {"dnn": "internet"}}}}},
        "FlowRules": [{"filter": "1.1.1.1/32", "precedence": 128, "snssai": "01010203", "dnn": "internet", "qosRef": 1},
                      {"filter": "1.1.1.1/32", "precedence": 127, "snssai": "01112233", "dnn": "internet", "qosRef": 2}],
        "QosFlows": [{"snssai": "01010203", "dnn": "internet", "qosRef": 1, "5qi": 8,
                      "mbrUL": "208 Mbps", "mbrDL": "208 Mbps", "gbrUL": "108 Mbps", "gbrDL": "108 Mbps"},
                     {"snssai": "01112233", "dnn": "internet", "qosRef": 2, "5qi": 7,
                      "mbrUL": "407 Mbps", "mbrDL": "407 Mbps", "gbrUL": "207 Mbps", "gbrDL": "207 Mbps"}],
        "ChargingDatas": [
            {"snssai": "01010203", "dnn": "", "filter": "", "chargingMethod": "Offline", "quota": "0", "unitCost": "1"},
            {"snssai": "01010203", "dnn": "internet", "filter": "1.1.1.1/32", "qosRef": 1, "chargingMethod": "Offline",
             "quota": "0", "unitCost": "1"},
            {"snssai": "01112233", "dnn": "", "filter": "", "chargingMethod": "Online", "quota": "100000", "unitCost": "1"},
            {"snssai": "01112233", "dnn": "internet", "filter": "1.1.1.1/32", "qosRef": 2, "chargingMethod": "Online",
             "quota": "5000", "unitCost": "1"}],
    }


def _id(args, name):
    v = args.get(name)
    if not isinstance(v, str) or not _ID.match(v):
        raise ValueError(f"{name}: letters, digits and dashes only (e.g. imsi-208930000000001, 20893)")
    return v


def _hex(args, name, default):
    v = args.get(name, default)
    if not isinstance(v, str) or not re.fullmatch(r"[0-9a-fA-F]{32}", v):
        raise ValueError(f"{name}: 32 hexadecimal characters")
    return v.lower()


def _merge(dst, src):
    for k, v in src.items():
        if isinstance(v, dict) and isinstance(dst.get(k), dict):
            _merge(dst[k], v)
        else:
            dst[k] = v
    return dst


def _out(code, data):
    if code >= 400:
        raise ValueError(f"the WebConsole answered HTTP {code}: {json.dumps(redact(data))[:500]}")
    return {"status": code, "result": redact(data)}


def call_tool(name, args):
    if name == "subscriber_list":
        return _out(*WC.call("GET", "/api/subscriber"))
    if name == "subscriber_get":
        code, data = stored(_id(args, "ueId"), _id(args, "servingPlmnId"))
        out = _out(code, data)
        if not has_key(data):
            out["warning"] = NO_KEY_WARNING
        return out
    if name == "tenant_users_get":
        return _out(*WC.call("GET", f"/api/tenant/{_id(args, 'tenantId')}/user"))
    if name in ("subscriber_create", "subscriber_create_multiple"):
        ue, plmn = _id(args, "ueId"), _id(args, "servingPlmnId")
        data = args.get("subscriberData")
        if data is not None and not isinstance(data, dict):
            raise ValueError("subscriberData must be an object")
        body = data or default_subscriber(ue, plmn, _hex(args, "key", TEST_K), _hex(args, "opc", TEST_OPC))
        if name == "subscriber_create":
            return _out(*WC.call("POST", f"/api/subscriber/{ue}/{plmn}", body))
        n = args.get("userNumber")
        if not isinstance(n, int) or isinstance(n, bool) or not 1 <= n <= 1000:
            raise ValueError("userNumber: an integer 1-1000")
        return _out(*WC.call("POST", f"/api/subscriber/{ue}/{plmn}/{n}", body))
    if name == "subscriber_update":
        ue, plmn = _id(args, "ueId"), _id(args, "servingPlmnId")
        if not isinstance(args.get("subscriberData"), dict):
            raise ValueError("subscriberData must be an object")
        stored(ue, plmn)        # the WebConsole's PUT creates a missing subscriber: an update never does
        return _out(*WC.call("PUT", f"/api/subscriber/{ue}/{plmn}", args["subscriberData"]))
    if name == "subscriber_patch":
        ue, plmn = _id(args, "ueId"), _id(args, "servingPlmnId")
        if not isinstance(args.get("patchData"), dict):
            raise ValueError("patchData must be an object")
        # a missing subscriber reads as an empty profile: merged and PUT, it would create a subscriber with no SIM key
        code, cur = stored(ue, plmn)
        if code != 200 or not isinstance(cur, dict):
            raise ValueError(f"the subscriber could not be read (HTTP {code})")
        merged = _merge(copy.deepcopy(cur), args["patchData"])
        return _out(*WC.call("PUT", f"/api/subscriber/{ue}/{plmn}", merged))
    if name == "subscriber_delete":
        return _out(*WC.call("DELETE", f"/api/subscriber/{_id(args, 'ueId')}/{_id(args, 'servingPlmnId')}"))
    if name == "subscriber_delete_multiple":
        subs = args.get("subscribers")
        if not isinstance(subs, list) or not subs or len(subs) > 1000:
            raise ValueError("subscribers: a list of 1-1000 {ueId, servingPlmnId}")
        body = [{"plmnID": _id(s, "servingPlmnId"), "ueId": _id(s, "ueId")} for s in subs if isinstance(s, dict)]
        if len(body) != len(subs):
            raise ValueError("every subscriber needs ueId and servingPlmnId")
        return _out(*WC.call("DELETE", "/api/subscriber", body))
    raise KeyError(name)


def tools():
    with open(MANIFEST) as f:
        declared = json.load(f)["tools"]
    # readOnlyHint: the manifest's word, so the platform's approval screen points out the tools that only read
    return [{"name": t["name"], "description": t["description"], "inputSchema": t["input_schema"],
             "annotations": {"readOnlyHint": t.get("read_only") is True}} for t in declared]


# ── MCP over streamable HTTP ──────────────────────────────────────────────────────────────────────────────────────
def _result(mid, result):
    return {"jsonrpc": "2.0", "id": mid, "result": result}


def _error(mid, code, message):
    return {"jsonrpc": "2.0", "id": mid, "error": {"code": code, "message": message}}


def handle(msg, session):
    """→ (reply or None, new session id or None, http status)."""
    if not isinstance(msg, dict) or msg.get("jsonrpc") != "2.0" or not isinstance(msg.get("method"), str):
        return _error(None, -32600, "invalid request"), None, 400
    method, mid, params = msg["method"], msg.get("id"), msg.get("params") or {}
    if method == "initialize":
        sid = uuid.uuid4().hex
        with _lock:
            now = time.time()
            for k in [k for k, t in _sessions.items() if now - t > SESSION_TTL_S]:
                _sessions.pop(k, None)
            _sessions[sid] = now
        ver = params.get("protocolVersion") if params.get("protocolVersion") in VERSIONS else VERSIONS[0]
        return _result(mid, {"protocolVersion": ver, "capabilities": {"tools": {"listChanged": False}},
                             "serverInfo": {"name": "free5gc-mcp", "version": "1"}}), sid, 200
    with _lock:
        if session not in _sessions:
            return _error(mid, -32001, "unknown session"), None, 404
        _sessions[session] = time.time()
    if mid is None:
        return None, None, 202
    if method == "ping":
        return _result(mid, {}), None, 200
    if method == "tools/list":
        return _result(mid, {"tools": tools()}), None, 200
    if method == "tools/call":
        name, args = params.get("name"), params.get("arguments") or {}
        if name not in {t["name"] for t in tools()} or not isinstance(args, dict):
            return _error(mid, -32602, f"unknown tool {name}"), None, 200
        try:
            out = call_tool(name, args)
        except (ValueError, KeyError, RuntimeError, OSError) as e:
            return _result(mid, {"content": [{"type": "text", "text": str(e)}], "isError": True}), None, 200
        return _result(mid, {"content": [{"type": "text", "text": json.dumps(out)}], "structuredContent": out}), None, 200
    return _error(mid, -32601, f"method not found: {method}"), None, 200


class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    timeout = 60

    def _send(self, code, body=b"", ctype="application/json", headers=None):
        self.send_response(code)
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/healthz":
            return self._send(200, b'{"ok": true}')
        self._send(405, b'{"error": "use POST"}')

    def do_DELETE(self):
        with _lock:
            _sessions.pop(self.headers.get("Mcp-Session-Id"), None)
        self._send(200)

    def do_POST(self):
        if self.path.split("?")[0] != "/mcp":
            return self._send(404, b'{"error": "not found"}')
        n = int(self.headers.get("Content-Length") or 0)
        if n <= 0 or n > MAX_BODY:
            return self._send(413, b'{"error": "body too large or empty"}')
        raw = self.rfile.read(n)
        why = check_token(self.headers.get(TOKEN_HEADER), raw)
        if why:
            return self._send(401, json.dumps({"error": why}).encode())
        try:
            msg = json.loads(raw)
        except ValueError:
            return self._send(400, json.dumps(_error(None, -32700, "parse error")).encode())
        reply, sid, code = handle(msg, self.headers.get("Mcp-Session-Id"))
        headers = {"Mcp-Session-Id": sid} if sid else {}
        if reply is None:
            return self._send(code, headers=headers)
        self._send(code, json.dumps(reply).encode(), headers=headers)

    def log_message(self, fmt, *a):      # no bodies, no arguments in the log
        print("[free5gc-mcp]", self.address_string(), self.command, self.path, flush=True)


if __name__ == "__main__":
    aud, why = expected_audience()
    print(f"[free5gc-mcp] http on {PORT}, WebConsole {WEBCONSOLE}, audience {aud or 'none (' + why + ')'}", flush=True)
    ThreadingHTTPServer(("0.0.0.0", PORT), H).serve_forever()
