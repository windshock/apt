FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    bash ca-certificates curl grep gawk coreutils \
    p7zip-full unzip file yara \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /work
COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

# copy only small helpers into image; repo itself is mounted read-only by compose
COPY env_utils.py /work/env_utils.py


