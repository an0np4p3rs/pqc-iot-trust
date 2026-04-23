FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive
ENV VIRTUAL_ENV=/opt/venv
ENV PATH="$VIRTUAL_ENV/bin:$PATH"
ENV LD_LIBRARY_PATH="/usr/local/lib:/usr/local/lib64:${LD_LIBRARY_PATH}"

RUN apt-get update && apt-get install -y \
    git \
    cmake \
    ninja-build \
    build-essential \
    python3 \
    python3-pip \
    python3-venv \
    libssl-dev \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN python3 -m venv $VIRTUAL_ENV

RUN git clone --depth 1 https://github.com/open-quantum-safe/liboqs.git /opt/liboqs && \
    cmake -S /opt/liboqs -B /opt/liboqs/build -GNinja \
    -DBUILD_SHARED_LIBS=ON \
    -DOQS_ENABLE_SIG_DILITHIUM=ON \
    -DOQS_ENABLE_KEM_KYBER=ON \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_POSITION_INDEPENDENT_CODE=ON && \
    ninja -C /opt/liboqs/build && \
    ninja -C /opt/liboqs/build install && \
    ldconfig

RUN git clone --depth 1 https://github.com/open-quantum-safe/liboqs-python.git /opt/liboqs-python && \
    pip install --no-cache-dir /opt/liboqs-python

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt
RUN pip uninstall -y oqs || true && pip install --no-cache-dir /opt/liboqs-python

COPY hub /app

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]
