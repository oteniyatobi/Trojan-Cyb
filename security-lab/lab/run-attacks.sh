#!/usr/bin/env bash
# Fires the five simulated attacks. Each rule matches a label word in the URL.
set -euo pipefail
for word in sqltest xsstest bruteforcetest scantest floodtest; do
  docker exec lab-attacker curl -s -o /dev/null "http://172.30.0.10/${word}"
  echo "sent /${word}"
done
echo "Wait about 15 seconds, then check fast.log and the Wazuh dashboard."
