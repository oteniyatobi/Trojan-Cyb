#!/usr/bin/env bash
docker rm -f lab-victim lab-attacker 2>/dev/null || true
docker network rm trojan-lab 2>/dev/null || true
echo "Lab removed."
