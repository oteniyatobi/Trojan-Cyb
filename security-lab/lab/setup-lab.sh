#!/usr/bin/env bash
# Creates a private Docker network (bridge trojan-br0) with a victim and an attacker.
set -euo pipefail

docker network inspect trojan-lab >/dev/null 2>&1 || \
  docker network create --driver bridge --subnet 172.30.0.0/24 \
    -o com.docker.network.bridge.name=trojan-br0 trojan-lab

docker rm -f lab-victim lab-attacker >/dev/null 2>&1 || true
docker run -d --name lab-victim --network trojan-lab --ip 172.30.0.10 nginx:alpine
docker run -d --name lab-attacker --network trojan-lab --ip 172.30.0.20 \
  --entrypoint sleep curlimages/curl infinity

ip -br addr show trojan-br0
echo "Lab ready. Victim 172.30.0.10, attacker 172.30.0.20."
