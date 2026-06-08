# Demo 01 — Basic attack-surface drift detection

NMAPDIFF is a **defensive change-detection** tool. It does not scan anything;
it ingests two nmap XML reports (`nmap -oX`) you already collected against an
**authorized** target and tells you what changed in the attack surface.

## The story

You run a weekly authorized scan of your lab subnet `10.0.0.0/29` and keep the
XML output as a baseline. One week later you scan again. Eyeballing two raw
nmap reports is error-prone, so you diff them.

* `baseline.xml` — last week's scan (2 hosts).
* `current.xml`  — this week's scan (3 hosts).

## Run it

```sh
python -m nmapdiff diff demos/01-basic/baseline.xml demos/01-basic/current.xml
```

JSON for piping into a SIEM / ticketing automation:

```sh
python -m nmapdiff diff demos/01-basic/baseline.xml demos/01-basic/current.xml --format json
```

## What you should see

NMAPDIFF surfaces every change that matters for triage:

* **New host** `10.0.0.12` appeared on the subnet — with **telnet (23)** and
  **RDP (3389)** open. That is exactly the kind of unauthorized / risky
  exposure a defender wants flagged immediately.
* **New port** `443/tcp (https)` opened on `web01` (`10.0.0.10`).
* **New port** `6379/tcp (redis)` opened on `db01` (`10.0.0.11`) — an
  unauthenticated cache exposed to the network is worth a ticket.
* **Service change**: `web01:80` upgraded `nginx 1.24.0 -> 1.27.0`.

Closed ports in the baseline are ignored (only open / open|filtered ports are
tracked), so noise stays low.

## Exit codes

* `0` — no changes (clean drift report)
* `1` — changes detected (findings present) — useful in CI/cron to alert
* `2` — usage / parse / IO error
