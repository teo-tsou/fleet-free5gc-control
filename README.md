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
          │  N2 (gNB→AMF)  ─── IntEdge binding ──►
          └─ N4 (SMF→UPF)  ◄── IntEdge binding ───
```

## Before deploying — set two addresses in `values.yaml`
Both come from your IntEdge cross-UC bindings:

- **`EDGE_UPF_N4_ADDR`** — the address the core SMF uses to reach the **edge
  UPF's N4** (the UPF binds PFCP on `0.0.0.0` and exposes the `upf-n4` NodePort;
  point this at whatever your N4 binding surfaces in core-5g).
- **`SMF_N4_ADDR`** — the SMF's own **fabric-reachable** PFCP address so the
  edge UPF can reply (its pod IP, or the address your SMF↔UPF binding exposes).

N2 is unchanged — the gNB already reaches the AMF via the N2 binding.

## Notes
- `deployUpf: false` is the only subchart toggle changed vs the full deployment.
- `n4network.enabled: false` puts SMF PFCP on the pod network (no Multus N4).
- The SMF's `userplaneInformation` keeps the **N3 endpoint** as the edge UPF's
  local ipvlan IP (`10.100.50.233`) — that's resolved locally in edge-5g.
- No `gtp5g-installer` dependency here (only the UPF needs the kernel module).
