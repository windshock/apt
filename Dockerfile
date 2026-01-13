FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    bash ca-certificates curl grep gawk coreutils openssl \
    p7zip-full unzip file yara \
    # FUSE userspace + libs (MemProcFS mount)
    fuse libfuse2 \
    # MemProcFS deps
    libusb-1.0-0 lz4 \
    # debugging helpers
    procps util-linux \
    git \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /work
COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

# K8s-friendly: bake required repo code into the image.
# Compose can still mount /work read-only, but K8s needs the code inside the image.
COPY . /work


