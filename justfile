build_container:
    docker buildx build --load -t ghcr.io/irateau/sam-bot:latest .

run_container: build_container
    docker run --rm -it \
    --name sam-bot \
    -p "3000:3000" \
    --mount "type=bind,src=$(pwd)/config.json,dst=/code/config.json" \
    ghcr.io/irateau/sam-bot:latest