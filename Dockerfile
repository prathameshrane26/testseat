FROM debian:bookworm-slim

# Install build tools and PostgreSQL libpq development headers
RUN apt-get update && apt-get install -y \
    build-essential \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY backend/ ./backend/

WORKDIR /app/backend

RUN make

EXPOSE 5000

CMD ["./server.exe"]