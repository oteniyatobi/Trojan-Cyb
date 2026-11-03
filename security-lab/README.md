# Security lab: Suricata, Wazuh and a virtual attack network

> **DRAFT.** Written from one laptop's setup (Ubuntu on WSL2). It has not been
> tested on a clean machine yet. Anything marked *unconfirmed* has not been run
> end to end.

Everything runs locally. The demo "attacks" are **simulated**: each rule fires on
a label word in a URL (for example `sqltest`), not on real attack behaviour. Say
so when presenting.

## How it fits together

attacker container -> victim container over a private bridge (`trojan-br0`) ->
Suricata sees the traffic and writes `eve.json` -> the Wazuh agent reads that
file -> the Wazuh Manager raises an alert -> the dashboard shows it.

## Requirements

- Ubuntu on WSL2 with systemd on. Check: `ps -p 1 -o comm=` prints `systemd`.
  If not, add `[boot]` and `systemd=true` to `/etc/wsl.conf`, then run
  `wsl --shutdown` in PowerShell.
- Docker engine running (`docker ps` works without an error).
- At least 4 CPU cores and about 8 GB RAM visible to WSL.
- A stable network. Captive-portal Wi-Fi breaks `apt` (`NOSPLIT` errors) and
  Docker pulls, so use a hotspot for the downloads.
- The Wazuh indexer needs this setting (persists across restarts):

```
echo "vm.max_map_count=262144" | sudo tee /etc/sysctl.d/99-wazuh.conf
sudo sysctl --system
```

## Stage 1: Wazuh in Docker

Clone it **outside this repo** and never commit it.

```
cd ~
git clone https://github.com/wazuh/wazuh-docker.git -b v4.14.9
cd wazuh-docker/single-node
docker compose -f generate-indexer-certs.yml run --rm generator
docker compose up -d
```

Check: `docker compose ps` shows three containers `Up`. Open
`https://localhost` (accept the certificate warning) and you see a login page.
The login is `INDEXER_USERNAME` and `INDEXER_PASSWORD` in that folder's
`docker-compose.yml`. Those defaults are public, so keep the ports local and
change them before exposing anything.

## Stage 2: Wazuh agent (installed directly)

The agent must not be newer than the Manager, so pin the version.

```
sudo apt install -y curl gnupg apt-transport-https
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | sudo gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import
sudo chmod 644 /usr/share/keyrings/wazuh.gpg
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | sudo tee /etc/apt/sources.list.d/wazuh.list
sudo apt update
sudo WAZUH_MANAGER="127.0.0.1" apt install -y wazuh-agent=4.14.9-1
sudo systemctl daemon-reload
sudo systemctl enable --now wazuh-agent
```

Check: the dashboard shows 1 active agent.

## Stage 3: Suricata

```
sudo apt update
sudo apt install -y suricata
ip route show default
sudo nano /etc/suricata/suricata.yaml
```

Under `af-packet:` set the first entry to your interface (usually `eth0`), then:

```
sudo suricata-update
sudo suricata -T -c /etc/suricata/suricata.yaml -v
sudo systemctl enable --now suricata
```

Check: `sudo tail /var/log/suricata/suricata.log` shows `Engine started`
(allow about a minute), and `/var/log/suricata/eve.json` exists.

## Stage 4: Make Wazuh read Suricata's alerts

From the repo root. Run this **once only**. `tee` is used because a plain `>>`
redirect would not get root rights.

```
sudo cp /var/ossec/etc/ossec.conf /var/ossec/etc/ossec.conf.bak
sudo grep -n suricata /var/ossec/etc/ossec.conf    # should print nothing
sudo tee -a /var/ossec/etc/ossec.conf < security-lab/wazuh/ossec-localfile.xml > /dev/null
sudo systemctl restart wazuh-agent
sudo grep eve.json /var/ossec/logs/ossec.log
```

Check: a line saying `Analyzing file: '/var/log/suricata/eve.json'`.

## Stage 5: Demo rules

Run once only (a repeated sid makes Suricata complain).

```
sudo tee -a /etc/suricata/rules/local.rules < security-lab/suricata/local.rules > /dev/null
sudo suricata-update --local /etc/suricata/rules/local.rules
sudo systemctl restart suricata
```

Wait for `Engine started` in the log before testing, because traffic sent
during startup is missed.

## Stage 6: Virtual attack network

```
./security-lab/lab/setup-lab.sh
```

Then make Suricata watch the bridge. In `/etc/suricata/suricata.yaml`, add this
entry under `af-packet:` after the `eth0` entry and **before**
`- interface: default`. Indentation matters, and use spaces only:

```
  - interface: trojan-br0
    cluster-id: 98
    cluster-type: cluster_flow
    defrag: yes
```

Then:

```
sudo suricata -T -c /etc/suricata/suricata.yaml -v
sudo systemctl restart suricata
```

After a reboot, start the lab first (`docker start lab-victim lab-attacker`),
then restart Suricata. Suricata errors if `trojan-br0` does not exist.

## Stage 7: Attack and verify

```
./security-lab/lab/run-attacks.sh
sleep 15
sudo tail -n 5 /var/log/suricata/fast.log
```

Check Wazuh got them:

```
docker exec single-node-wazuh.manager-1 sh -c "grep -o 'Suricata: Alert - [^\"]*' /var/ossec/logs/alerts/alerts.json | sort | uniq -c"
```

`docker compose exec` only works from the Wazuh folder, but `docker exec` with
the container name works from anywhere. `alerts.json` only holds the current
day, so older alerts are in the dashboard (Threat Hunting).

## Idle baseline

Leave everything idle for 10 to 15 minutes without running `sudo`, then:

```
free -h
docker stats --no-stream
systemd-cgtop -b -n 2 -d 10 | grep -E "suricata|wazuh-agent"
```

Use the second block of `systemd-cgtop` output. Note your machine's specs and
that this is a laptop in WSL, not the target server.

## Known issues

- `sudo` commands create Wazuh alerts, and a `grep suricata` on alerts can match
  your own `sudo` command. Filter on `Suricata: Alert` instead.
- Flaky Wi-Fi produces `SURICATA STREAM excessive retransmissions` alerts. They
  are noise, not attacks.
- On a captive-portal network, `curl http://example.com/...` may return the
  login page, so the rule matches the redirect and not the request.

## Not covered or unconfirmed

- The integration script that sends alerts to the backend (`POST /v1/analyze`),
  and how a container reaches the backend (`127.0.0.1` inside a container is the
  container itself).
- The Groq review step and the dashboard.
- Running this on a machine other than the author's.
