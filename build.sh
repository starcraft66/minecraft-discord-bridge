#!/bin/bash
set -e

docker login --username $DOCKER_HUB_USERNAME --password $DOCKER_HUB_PASSWORD
docker login --username $DOCKER_GH_USERNAME --password $DOCKER_GH_PASSWORD $DOCKER_GH_REGISTRY_URL
echo "Building docker image."
docker build --tag starcraft66/minecraft-discord-bridge:latest --tag docker.pkg.github.com/starcraft66/minecraft-discord-bridge/minecraft-discord-bridge:latest .
echo "Pushing image to docker hub."
docker push starcraft66/minecraft-discord-bridge:latest
echo "Pushing image to github packages."
docker push docker.pkg.github.com/starcraft66/minecraft-discord-bridge/minecraft-discord-bridge:latest
echo "Done building."
