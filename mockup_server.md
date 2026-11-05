# MCP Mockup Server — Decision & Violation ID

> **Reminder:** The verdict is **not** driven by the server `--action` flag (allow/deny). You can
> start the server in either mode — it makes no difference. What matters is the **traffic sent**
> (trigger header present or not) and the **`--violation-id`** the server was started with.

---

## The two switches

- **Attack vs legit** → the block-trigger header (`X-RDWR-Attack`) on the request.
  Present = attack, absent = legit. Only the header **name** matters; the value can be anything.
- **ALLOW vs REPORT-ONLY, and the attack name** → the `--violation-id`:
  - empty / omitted → ALLOW (no violation)
  - `ddos` → classified as `MCP DDoS`
  - anything else (e.g. `fw`) → classified as `MCP FW`

---

## The three outcomes

| Traffic type | `--violation-id` | Outcome | Trap |
|--------------|------------------|---------|------|
| Legit        | empty            | ALLOW   | none |
| Legit        | value        | REPORT-ONLY | forward trap, named by value |
| Attack       | value            | BLOCK   | high-drop trap, named by value |

---

## Server command + traffic examples → outcome

**ALLOW** — legit traffic, empty violation-id:
```bash
# server
nohup python3 /root/http_avro_server.py --mode https --port 4433 --action deny --deny-header "X-RDWR-Attack" --violation-id "" --log /root/server_access.log --ip 2.2.2.2 --key /root/client.key --cert /root/client.crt --mtls --trust-ca /root/ca.crt > /root/mockup_server_output.log 2>&1 &
# traffic
curl -vk https://1.1.2.2/
```
➡️ ALLOW. No traps.

**REPORT-ONLY (DDoS)** — legit traffic, violation-id=ddos:
```bash
# server
nohup python3 /root/http_avro_server.py --mode https --port 4433 --action deny --deny-header "X-RDWR-Attack" --violation-id "ddos" --log /root/server_access.log --ip 2.2.2.2 --key /root/client.key --cert /root/client.crt --mtls --trust-ca /root/ca.crt > /root/mockup_server_output.log 2>&1 &
# traffic
curl -vk https://1.1.2.2/
```
➡️ REPORT-ONLY → forward trap `MCP DDoS` (no high-drop).

**REPORT-ONLY (FW)** — legit traffic, violation-id=fw:
```bash
# server
nohup python3 /root/http_avro_server.py --mode https --port 4433 --action deny --deny-header "X-RDWR-Attack" --violation-id "fw" --log /root/server_access.log --ip 2.2.2.2 --key /root/client.key --cert /root/client.crt --mtls --trust-ca /root/ca.crt > /root/mockup_server_output.log 2>&1 &
# traffic
curl -vk https://1.1.2.2/
```
➡️ REPORT-ONLY → forward trap `MCP FW` (no high-drop).

**BLOCK (DDoS)** — attack traffic (header present), violation-id=ddos:
```bash
# server
nohup python3 /root/http_avro_server.py --mode https --port 4433 --action deny --deny-header "X-RDWR-Attack" --violation-id "ddos" --log /root/server_access.log --ip 2.2.2.2 --key /root/client.key --cert /root/client.crt --mtls --trust-ca /root/ca.crt > /root/mockup_server_output.log 2>&1 &
# traffic
curl -vk https://1.1.2.2/ -H "X-RDWR-Attack: 1"
```
➡️ BLOCK → high-drop trap `MCP DDoS` (no forward).

**BLOCK (FW)** — attack traffic (header present), violation-id=fw:
```bash
# server
nohup python3 /root/http_avro_server.py --mode https --port 4433 --action deny --deny-header "X-RDWR-Attack" --violation-id "fw" --log /root/server_access.log --ip 2.2.2.2 --key /root/client.key --cert /root/client.crt --mtls --trust-ca /root/ca.crt > /root/mockup_server_output.log 2>&1 &
# traffic
curl -vk https://1.1.2.2/ -H "X-RDWR-Attack: anything"
```
➡️ BLOCK → high-drop trap `MCP FW` (no forward).

---

> Note: `--violation-id` is a start-time flag, so changing it requires restarting the server.
> Only `--violation-id` changes between runs; everything else stays the same.
