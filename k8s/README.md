## IR on Kubernetes (PoC)

This repo currently supports Docker Compose first, but you can run the IR Orchestrator (+ mTLS Gateway)
on Kubernetes as a PoC.

### Prereqs

- A container registry (Harbor) you can push to
- `kubectl` configured (kubeconfig)
- A writable StorageClass for a PVC (evidence DB + buckets + PKI)

### Build & push images (Windows/Linux/macOS build host with Docker)

Pick an image repo and tag, e.g.:

- `IMAGE_REPO=dev.pcr.kr/dfir/apt-ir`
- `IMAGE_TAG=dev-$(date +%Y%m%d-%H%M%S)`

Then:

```bash
export IMAGE_REPO="dev.pcr.kr/dfir/apt-ir"
export IMAGE_TAG="dev-$(date +%Y%m%d-%H%M%S)"

# login without echoing secrets:
cat robot-token.txt | docker login dev.pcr.kr --username 'robot$...+dfir' --password-stdin

docker build -t "${IMAGE_REPO}:${IMAGE_TAG}" .
docker push "${IMAGE_REPO}:${IMAGE_TAG}"
```

### Deploy (kubectl)

Edit `k8s/kustomization.yaml` to set the image repo/tag, then:

```bash
kubectl apply -k k8s/
```

### UI

- Orchestrator UI (Basic Auth): `http://<node-ip>:30080/ui`  (NodePort)
- Defaults are in `k8s/secret-ir.yaml` (change them!)

