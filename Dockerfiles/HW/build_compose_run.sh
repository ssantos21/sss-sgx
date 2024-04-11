set -e

docker compose build

docker volume create --driver local --opt type=tmpfs --opt device=tmpfs --opt o=rw aesmd-socket

docker compose --verbose up
