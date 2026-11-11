# Kubernetes manifests — SKELETON

These manifests are a **skeleton**, not a supported production deployment. They
encode the shape from [docs/ARCHITECTURE.md](../../docs/ARCHITECTURE.md) so the
"Kubernetes-ready" posture is visible and reviewable. Nothing here has been
applied against a live cluster.

Read this page before `kubectl apply`, and expect to edit values: image tag,
ingress class, hosts, storage class, and the master-key Secret.

## What the binary actually is

Pigeon is **one binary** with two documented subcommands:

| Command | What it runs |
|---|---|
| `pigeon serve` | every service in one process: `api`, `mcp` (HTTP), `web` (optional webmail), `smtp-in`, `smtp-out` |
| `pigeon mcp` | the MCP server over stdio (for agent clients, not for a Deployment) |

There is no documented "API only" or "SMTP only" switch yet. The two Deployment
files therefore represent two *postures*, not two code paths:

| File | Posture | Reality today |
|---|---|---|
| `deployment-smtp.yaml` | stateful single replica + PVC: the honest single-node mode | works as written |
| `deployment-api.yaml` | stateless multi-replica tier behind the ingress | aspirational; same binary, needs a per-service enablement knob and a shared store |

## Scaling path: the `Storage` trait seam

ADR 0002 puts every read and write behind a `Storage` trait (`store` crate).
That trait boundary is the migration path, in this order:

1. **Vertical** — one pod, one SQLite file on a PVC. Target load is 10⁵–10⁶
   messages/day on 2 vCPU. Start here.
2. **Split tiers** — move `api`/`mcp`/`web` off the SMTP pod. Requires the
   per-service enablement knob above; still one shared store.
3. **Shared store** — implement the `Storage` trait over Postgres/S3. Only then
   does `replicas: 2` mean anything for write tiers; the queue's claim
   tokens (`claimed_at`/`claim_token`) already support multiple workers.

## When to move off SQLite

Move to the shared-DB backend when **any** of these becomes true:

- more than one node must serve the API (or `replicas > 1` matters for uptime);
- the working set no longer fits comfortably on one volume, or you need
  point-in-time restore the volume snapshot can't give you;
- mail volume outgrows one pod's CPU (10⁶ msgs/day is the documented ceiling);
- you need zone-level availability: an RWO PVC is a single-node dependency.

Before that, a bigger instance is cheaper than a distributed store.

## Order of operations

```bash
# 1. image — build and push the tag you will actually run
docker build -t ghcr.io/dantoniomarte/pigeon-mail:latest .
docker push ghcr.io/dantoniomarte/pigeon-mail:latest

# 2. namespace
kubectl apply -f namespace.yaml

# 3. master key — create it from a file, do NOT apply secret-masterkey.yaml
openssl rand -hex 32 > master.key && chmod 0600 master.key
kubectl -n pigeon create secret generic pigeon-masterkey \
  --from-file=master.key=./master.key
# back the key up offline, then remove the local copy
shred -u master.key

# 4. config + storage + workloads
kubectl apply -f configmap.yaml
kubectl apply -f deployment-smtp.yaml     # PVC + the stateful tier
kubectl apply -f service-smtp.yaml        # NodePort + optional LoadBalancer
# split posture only, once the binary supports it:
# kubectl apply -f deployment-api.yaml -f service-api.yaml -f ingress.yaml

# 5. health
kubectl -n pigeon get pods
kubectl -n pigeon exec deploy/pigeon-smtp -- /bin/sh   # fails: distroless, expected

# Nothing publishes :8000 on the node (service-api.yaml is ClusterIP and is not
# applied in the single-replica posture), so probe through a port-forward:
kubectl -n pigeon port-forward deploy/pigeon-smtp 8000:8000 &
curl -fsS http://localhost:8000/healthz
curl -fsS http://localhost:8000/readyz
# (or `kubectl -n pigeon port-forward svc/pigeon-api 8000:8000` in split posture)
```

`secret-masterkey.yaml` exists only to document the shape of the Secret. Its
`stringData` value is a placeholder that the server will reject.

## Hard requirements

- **uid/gid 10001** — baked into the image; every pod runs `runAsNonRoot` with
  `readOnlyRootFilesystem: true`. Anything that writes must be a mounted volume
  (`/var/lib/pigeon`, `/tmp`).
- **Master key is a file**, mounted at `/etc/pigeon/master.key` from the
  `pigeon-masterkey` Secret. Never an env var, never a ConfigMap.
- **`/var/lib/pigeon` must not be tmpfs** — SQLite durability (ADR 0002).
- **Port 25** — see `service-smtp.yaml`: hostPort, hostNetwork, or a
  LoadBalancer with `externalTrafficPolicy: Local`. Only one MTA per IP:25.
- **Probes** — `/healthz` liveness, `/readyz` readiness (store reachable, key
  present). There is no container `HEALTHCHECK`: the image is distroless.

## Known gaps (deliberate, tracked here)

- No `NetworkPolicy`, `PodDisruptionBudget`, `HorizontalPodAutoscaler` or
  `ServiceAccount`/RBAC: nothing to protect until the workloads are real.
- `ingress.yaml` is HTTP-only workload ingress; SMTP never goes through it.
- TLS for SMTP (STARTTLS on 25/587) is the server's job, not the ingress'.
