# fleet-free5gc-control

free5gc **5G core control plane (no UPF)** as a Rancher Fleet bundle.

This is the split-deployment counterpart to [`fleet-free5gc-upf`](https://github.com/teo-tsou/fleet-free5gc-upf):

| Repo | Deploy to | Contains |
|------|-----------|----------|
| **fleet-free5gc-control** (this) | core UC (`core-5g`) | every NF **except the UPF** |
| fleet-free5gc-upf | edge UC (`edge-5g`) | the UPF, next to the gNB |

## Why split it
With one UPF in the core, the **N3 GTP-U user plane can't cross UCs** — the
SMF hands the gNB a Multus N3 IP that the OVN-IC fabric doesn't route, so the
session comes up but no data flows. Putting the UPF at the edge keeps **N3 +
N6 local**; only the **control plane** crosses UCs:

```
edge-5g                         core-5g
┌───────────────┐               ┌─────────────────────────────┐
│ gNB ──N3──► UPF │             │ AMF  SMF  NRF  AUSF  UDM ... │
│         │  └─N6─► internet     │                             │
└─────────┼─────┘               └─────────────────────────────┘
          │  N2 (gNB→AMF)   ── `amf` binding ──►
          └─ N4 (SMF⇄UPF)   `n4` + `smf` bindings ⇄
```

## Zero-touch — nothing to hand-edit
PFCP is bidirectional, and **both legs ride IntEdge cross-UC bindings by name**,
so there are no addresses to set per deployment:

| Leg | Direction | How it resolves |
|-----|-----------|-----------------|
| **N2** | gNB → AMF | `amf` binding (NGAP) |
| **N4 forward** | SMF → UPF | SMF `userplaneInformation` nodeID = `n4.upstream.svc.cluster.local` (the `n4` binding → edge UPF's `upf-n4` NodePort) |
| **N4 reverse** | UPF → SMF | SMF advertises nodeID `smf.upstream.svc.cluster.local`; the edge UPF resolves that locally via its `smf` binding → this SMF's `smf-n4` NodePort |

Just deploy in order — **UPF (edge) → control (core) → UERANSIM (edge)** — and
make sure the matching IntEdge bindings (`n4`, `smf`, `amf`) are wired between
the UCs. No pod IPs, no manual `values.yaml` edits.

## Notes
- `deployUpf: false` is the only subchart toggle changed vs the full deployment.
- `n4network.enabled: false` puts SMF PFCP on the pod network (no Multus N4).
- `smf-n4` is a NodePort exposing the SMF's PFCP so the reverse `smf` binding can
  reach it (mirrors the UPF's `upf-n4` on the forward leg).
- The SMF's `userplaneInformation` keeps the **N3 endpoint** as the edge UPF's
  local ipvlan IP (`10.100.50.233`) — that's resolved locally in edge-5g.
- No `gtp5g-installer` dependency here (only the UPF needs the kernel module).

## MCP server (AI assistant)

The chart also runs `free5gc-mcp` (`charts/templates/free5gc-mcp.yaml`, code in `charts/files/free5gc_mcp.py`): the
platform's cluster assistant manages this core's subscribers through MCP. Its tools follow
[free5gc-MCP](https://github.com/q1317540161/free5gc-MCP) (same names and arguments, same default subscriber), ported
to Python and served the way the platform expects an edge app's MCP server:

| Tool | What it does | Approval |
|---|---|---|
| `subscriber_list`, `subscriber_get`, `tenant_users_get` | read | none (read-only) |
| `subscriber_create`, `subscriber_create_multiple` | add subscribers (default profile, free5GC test keys unless `key`/`opc` given) | per call |
| `subscriber_update`, `subscriber_patch` | change a profile (patch merges into the current one) | per call |
| `subscriber_delete`, `subscriber_delete_multiple` | remove subscribers | per call |

- `mcp-manifest.json` (repo root) declares the server and the tools; the platform reads it at the signed commit it
  deploys. `charts/files/mcp-manifest.json` is a byte-identical copy for the chart (keep both the same).
- Only the platform can call it: every request carries the platform's signed, single-use token
  (`X-Platform-Token`, ECDSA P-256, bound to this namespace and the request body). The key arrives through Fleet
  (`fleet.yaml`: `${ .ClusterValues.platformMcpKey }`); without it every call is refused.
- SIM keys (K, OPc, OP) are redacted from every result, so the assistant's model never sees them.
- Not included: the original server's shell, systemd, kubectl and Helm tools. The platform deploys and upgrades free5GC.
- The server logs into the WebConsole (`webui-service:5000`) with `mcp.webconsoleUser` / `mcp.webconsolePassword`
  (a Secret; free5GC's default admin by default). `mcp.enabled: false` removes it.
- Tests: `python3 tests/test_free5gc_mcp.py` (a fake WebConsole, real platform tokens).
