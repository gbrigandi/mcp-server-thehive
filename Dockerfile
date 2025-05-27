# Multi-stage build for TheHive MCP Server
FROM rust:1.75-slim as builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /app

# Copy dependency files
COPY Cargo.toml Cargo.lock ./

# Copy source code
COPY src/ ./src/

# Build the application
RUN cargo build --release

# Runtime stage
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Create app user
RUN useradd -r -s /bin/false appuser

# Create app directory
WORKDIR /app

# Copy the binary from builder stage
COPY --from=builder /app/target/release/mcp-server-thehive /app/

# Change ownership to app user
RUN chown -R appuser:appuser /app

# Switch to app user
USER appuser

# Set environment variables
ENV RUST_LOG=info
ENV THEHIVE_URL=http://localhost:9000/api
ENV VERIFY_SSL=false

# Expose port (if needed for future HTTP transport)
EXPOSE 8080

# Run the application
CMD ["./mcp-server-thehive"]
