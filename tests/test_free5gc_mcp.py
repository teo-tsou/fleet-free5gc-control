#!/usr/bin/env python3
"""Tests for charts/files/free5gc_mcp.py against a fake free5GC WebConsole, with real platform tokens (ECDSA P-256).
Run: python3 tests/test_free5gc_mcp.py   (needs `cryptography`)."""
import base64, hashlib, importlib.util, json, os, sys, threading, time, urllib.request, urllib.error, uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FAILS = []
def check(name, cond, detail=""):
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  [{detail}]")); cond or FAILS.append(name)

# ── fake WebConsole ──
DB = {}
LOG = []
class WC(BaseHTTPRequestHandler):
    def _j(self, code, obj):
        b = json.dumps(obj).encode(); self.send_response(code); self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
    def _body(self):
        n = int(self.headers.get("Content-Length") or 0); return json.loads(self.rfile.read(n)) if n else None
    def _auth(self):
        return self.headers.get("Token") == "tok-1"
    def do_POST(self):
        LOG.append(("POST", self.path))
        if self.path == "/api/login":
            b = self._body(); return self._j(200 if b == {"username": "admin", "password": "pw"} else 401, {"access_token": "tok-1"})
        if not self._auth(): return self._j(401, {})
        p = self.path.split("/")   # /api/subscriber/<ue>/<plmn>[/<n>]
        body = self._body()
        if len(p) == 6:
            n = int(p[5]); base = int(p[3].split("-")[1])
            for i in range(n): DB[(f"imsi-{base + i}", p[4])] = body
            return self._j(201, {})
        DB[(p[3], p[4])] = body; return self._j(201, {})
    def do_GET(self):
        LOG.append(("GET", self.path))
        if not self._auth(): return self._j(401, {})
        if self.path == "/api/subscriber":
            return self._j(200, [{"ueId": k[0], "plmnID": k[1]} for k in DB])
        p = self.path.split("/")
        if p[2] == "tenant": return self._j(200, [{"email": "admin"}])
        v = DB.get((p[3], p[4])); return self._j(200 if v else 404, v or {})
    def do_PUT(self):
        LOG.append(("PUT", self.path))
        if not self._auth(): return self._j(401, {})
        p = self.path.split("/"); DB[(p[3], p[4])] = self._body(); return self._j(204 if False else 200, {})
    def do_DELETE(self):
        LOG.append(("DELETE", self.path))
        if not self._auth(): return self._j(401, {})
        if self.path == "/api/subscriber":
            for s in self._body(): DB.pop((s["ueId"], s["plmnID"]), None)
            return self._j(200, {})
        p = self.path.split("/"); DB.pop((p[3], p[4]), None); return self._j(200, {})
    def log_message(self, *a): pass

wc = ThreadingHTTPServer(("127.0.0.1", 0), WC); threading.Thread(target=wc.serve_forever, daemon=True).start()

# ── the server under test ──
key = ec.generate_private_key(ec.SECP256R1())
pem = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
os.environ.update(PLATFORM_KEY=base64.b64encode(pem).decode(), POD_NAMESPACE="free5gc", WEBCONSOLE_URL=f"http://127.0.0.1:{wc.server_port}",
                  WEBCONSOLE_USER="admin", WEBCONSOLE_PASSWORD="pw", MANIFEST=os.path.join(ROOT, "charts/files/mcp-manifest.json"))
spec = importlib.util.spec_from_file_location("srv", os.path.join(ROOT, "charts/files/free5gc_mcp.py"))
srv = importlib.util.module_from_spec(spec); spec.loader.exec_module(srv)
httpd = ThreadingHTTPServer(("127.0.0.1", 0), srv.H); threading.Thread(target=httpd.serve_forever, daemon=True).start()
URL = f"http://127.0.0.1:{httpd.server_port}/mcp"

def token(body, aud="mcp:ns/free5gc", jti=None):
    now = int(time.time())
    payload = json.dumps({"iss": "platform-hub", "aud": aud, "body": hashlib.sha256(body).hexdigest(), "iat": now, "exp": now + 60,
                          "jti": jti or uuid.uuid4().hex}).encode()
    sig = key.sign(payload, ec.ECDSA(hashes.SHA256()))
    e = lambda b: base64.urlsafe_b64encode(b).decode().rstrip("=")
    return e(payload) + "." + e(sig)

SID = [None]
def rpc(method, params=None, tok=True, aud="mcp:ns/free5gc", raw_token=None):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}}).encode()
    req = urllib.request.Request(URL, data=body, method="POST")
    req.add_header("Content-Type", "application/json")
    if tok: req.add_header("X-Platform-Token", raw_token or token(body, aud))
    if SID[0]: req.add_header("Mcp-Session-Id", SID[0])
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            if r.headers.get("Mcp-Session-Id"): SID[0] = r.headers["Mcp-Session-Id"]
            return r.status, json.loads(r.read() or b"null")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"null")

def call(name, args):
    code, r = rpc("tools/call", {"name": name, "arguments": args})
    res = r["result"]; return res.get("isError", False), (res.get("structuredContent") or res["content"][0]["text"])

# platform token
code, r = rpc("initialize", {"protocolVersion": "2025-06-18"}, tok=False)
check("no token → 401", code == 401 and "no platform token" in r["error"])
code, r = rpc("initialize", {"protocolVersion": "2025-06-18"}, aud="mcp:ns/other")
check("token for another app → 401", code == 401 and "another app" in r["error"])
body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}).encode()
code, r = rpc("initialize", {"protocolVersion": "2025-06-18"}, raw_token=token(body + b" "))
check("token for another body → 401", code == 401 and "another request" in r["error"])
code, r = rpc("initialize", {"protocolVersion": "2025-06-18"})
check("valid token → initialize, a session", code == 200 and SID[0] and r["result"]["serverInfo"]["name"] == "free5gc-mcp")
code, r = rpc("tools/list")
manifest = json.load(open(os.path.join(ROOT, "mcp-manifest.json")))
check("tools/list = the signed manifest (9 tools, nothing more)",
      [t["name"] for t in r["result"]["tools"]] == [t["name"] for t in manifest["tools"]] and len(manifest["tools"]) == 9)
_ro = {t["name"]: t.get("annotations", {}).get("readOnlyHint") for t in r["result"]["tools"]}
check("tools/list: readOnlyHint = the manifest's read_only (list, get, tenant users read; the rest change)",
      _ro == {t["name"]: t["read_only"] for t in json.load(open(os.path.join(ROOT, "mcp-manifest.json")))["tools"]}
      and _ro["subscriber_list"] is True and _ro["subscriber_delete"] is False)

# subscribers
err, out = call("subscriber_create", {"ueId": "imsi-208930000000001", "servingPlmnId": "20893"})
sub = DB.get(("imsi-208930000000001", "20893")) or {}
check("create with the default profile (free5GC's test keys, two slices)", not err and
      sub["AuthenticationSubscription"]["permanentKey"]["permanentKeyValue"] == srv.TEST_K and len(sub["SessionManagementSubscriptionData"]) == 2)
err, out = call("subscriber_get", {"ueId": "imsi-208930000000001", "servingPlmnId": "20893"})
txt = json.dumps(out)
check("get: SIM keys redacted in the result (K and OPc never reach the model)",
      not err and srv.TEST_K not in txt and srv.TEST_OPC not in txt and '"[redacted]"' in txt)
err, out = call("subscriber_create_multiple", {"ueId": "imsi-208930000000010", "servingPlmnId": "20893", "userNumber": 3,
                                               "key": "00112233445566778899aabbccddeeff", "opc": "ffeeddccbbaa99887766554433221100"})
check("create_multiple: 3 consecutive SUPIs with the given keys", not err and ("imsi-208930000000012", "20893") in DB
      and DB[("imsi-208930000000011", "20893")]["AuthenticationSubscription"]["opc"]["opcValue"] == "ffeeddccbbaa99887766554433221100")
err, out = call("subscriber_list", {})
check("list: all 4", not err and len(out["result"]) == 4)
err, out = call("subscriber_patch", {"ueId": "imsi-208930000000001", "servingPlmnId": "20893",
                                      "patchData": {"AccessAndMobilitySubscriptionData": {"subscribedUeAmbr": {"uplink": "500 Mbps"}}}})
s = DB[("imsi-208930000000001", "20893")]
check("patch: merged into the current profile (other fields kept)", not err
      and s["AccessAndMobilitySubscriptionData"]["subscribedUeAmbr"] == {"uplink": "500 Mbps", "downlink": "2 Gbps"}
      and s["AuthenticationSubscription"]["permanentKey"]["permanentKeyValue"] == srv.TEST_K)
err, out = call("subscriber_delete_multiple", {"subscribers": [{"ueId": "imsi-208930000000010", "servingPlmnId": "20893"},
                                                               {"ueId": "imsi-208930000000011", "servingPlmnId": "20893"}]})
check("delete_multiple", not err and ("imsi-208930000000010", "20893") not in DB and ("imsi-208930000000012", "20893") in DB)
err, out = call("subscriber_delete", {"ueId": "imsi-208930000000012", "servingPlmnId": "20893"})
check("delete", not err and ("imsi-208930000000012", "20893") not in DB)
err, out = call("subscriber_get", {"ueId": "../../api/login", "servingPlmnId": "20893"})
check("a path trick in an id is refused before any call", err and "letters, digits and dashes" in out)
err, out = call("subscriber_get", {"ueId": "imsi-1", "servingPlmnId": "20893"})
check("WebConsole 404 → a tool error, not a crash", err and "HTTP 404" in out)
err, out = call("tenant_users_get", {"tenantId": "t-1"})
check("tenant users", not err and out["result"] == [{"email": "admin"}])
code, r = rpc("tools/call", {"name": "local_free5gc_start", "arguments": {}})
check("a lifecycle tool of the original server does not exist here", "error" in r and "unknown tool" in r["error"]["message"])
srv.WC.token = "stale"
err, out = call("subscriber_list", {})
check("a refused WebConsole token → one re-login, the call succeeds", not err and srv.WC.token == "tok-1")
os.environ["PLATFORM_KEY"] = ""
code, r = rpc("tools/list")
check("no platform key configured → every call refused", code == 401 and "no platform key" in r["error"])
print("ALL PASSED" if not FAILS else f"{len(FAILS)} FAILED: {FAILS}"); sys.exit(1 if FAILS else 0)
