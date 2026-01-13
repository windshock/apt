## IR on Kubernetes (PoC)

This repo currently supports Docker Compose first, but you can run the IR Orchestrator (+ mTLS Gateway)
on Kubernetes as a PoC.

### Prereqs

- A container registry (Harbor) you can push to
- `kubectl` configured (kubeconfig)
- A writable StorageClass for a PVC (evidence DB + buckets + PKI)

### Build & push images (Windows/Linux/macOS build host with Docker)

Pick an image repo and tag, e.g.:

- `IMAGE_REPO=dev.pcr.kr/1004276/apt-ir`
- `IMAGE_TAG=dev-$(date +%Y%m%d-%H%M%S)`

Then:

```bash
export IMAGE_REPO="dev.pcr.kr/1004276/apt-ir"
export IMAGE_TAG="dev-$(date +%Y%m%d-%H%M%S)"

# login without echoing secrets:
cat robot-token.txt | docker login dev.pcr.kr --username 'robot$...+dfir' --password-stdin

docker build -t "${IMAGE_REPO}:${IMAGE_TAG}" .
docker push "${IMAGE_REPO}:${IMAGE_TAG}"
```

### Create imagePullSecret (Harbor)

Create a pull secret in the `ir` namespace so Pods can pull from Harbor:

```bash
kubectl -n ir create secret docker-registry harbor-regcred \
  --docker-server=dev.pcr.kr \
  --docker-username='robot$...+dfir' \
  --docker-password='<robot-secret>' \
  --dry-run=client -o yaml | kubectl apply -f -
```

### Deploy (kubectl)

Edit `k8s/kustomization.yaml` to set the image repo/tag, then:

```bash
kubectl apply -k k8s/
```

### Use your own TLS certificate for `dfir.skplanet.com` (recommended)

By default, the gateway uses an internally generated TLS cert (`/data/ir/pki/server.*.pem`).
If you already have a valid cert+key (e.g. in your local `skplanet.com/` folder), create a TLS secret
and the gateway will **automatically** prefer it.

Create the secret (cert should include fullchain if you have intermediates):

```bash
kubectl -n ir create secret tls ir-gateway-tls \
  --cert /path/to/fullchain.pem \
  --key  /path/to/privkey.pem \
  --dry-run=client -o yaml | kubectl apply -f -
```

Then restart the gateway:

```bash
kubectl -n ir rollout restart deploy/ir-gateway
```

### Storage (NAS / NFS)

This PoC uses a shared RWX volume so `ir-init`, `ir-orchestrator`, and `ir-gateway` can share `/data/ir/*`.
We provide a static NFS PV/PVC example:

- PV: `k8s/pv-ir-nfs.yaml` (server/path must match your NAS export)
- PVC: `k8s/pvc-ir.yaml` binds to that PV (`volumeName`)

### UI

- Orchestrator UI (Basic Auth): `http://<node-ip>:30080/ui`  (NodePort)
- Defaults are in `k8s/secret-ir.yaml` (change them!)

