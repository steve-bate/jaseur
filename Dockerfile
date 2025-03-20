FROM ubuntu:22.04 AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    git \
    libssl-dev \
    libboost-all-dev \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy source files
COPY . .

# Build the application
RUN mkdir build && cd build \
    && cmake .. \
    && make -j$(nproc) jaseur

# Runtime image
FROM ubuntu:22.04

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Copy the built executable
COPY --from=builder /app/build/jaseur /usr/local/bin/
COPY --from=builder /app/jaseur-docker.toml /app/jaseur.toml

WORKDIR /app

# Expose the default port
EXPOSE 9000

ARG CACHEBUST=1
RUN echo "$CACHEBUST" && ls -l /app

# Run the server
CMD ["jaseur", "serve"]