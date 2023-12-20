# Start from a small base image
FROM debian:buster-slim

# Set a working directory
WORKDIR /app

# Copy the compiled binary from your host machine into the Docker image
COPY ./target/release/susspekt /app/

# Set the binary as the entrypoint of the container
ENTRYPOINT ["/app/susspekt"]

# Ensure that all command line arguments are passed to the binary
CMD []
