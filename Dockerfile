FROM debian:bookworm-slim

# Install build tools and PostgreSQL libpq development libraries
RUN apt-get update && apt-get install -y \
    build-essential \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy backend files into container
COPY backend/ ./backend/

WORKDIR /app/backend

# Compile C server with PostgreSQL support
RUN make

EXPOSE 5000

CMD ["./server.exe"]