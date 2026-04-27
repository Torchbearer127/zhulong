FROM python:3.12-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        bash \
        ca-certificates \
        curl \
        git \
        iputils-ping \
        jq \
        netcat-openbsd \
        npm \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace

RUN python3 -m pip install --no-cache-dir requests python-docx

CMD ["bash"]
