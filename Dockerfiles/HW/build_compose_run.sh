set -e
docker build  --target aesm -t sgx_aesm -f ./Dockerfile ./

docker build --target sample -t sgx_sample -f ./Dockerfile ./

docker volume create --driver local --opt type=tmpfs --opt device=tmpfs --opt o=rw aesmd-socket

docker compose --verbose up
