# SigScan: Signature-Based Intrusion Detection Using the Aho-Corasick Algorithm

## Problem Statement

A network Intrusion Detection System (IDS) has to check every packet for known attack
signatures such as `union select` or `../`. Checking each signature separately costs
O(n × k) for a payload of length n and k signatures, which is too slow at line rate.
We need to find **all** signatures in a payload in **one pass**.

## Algorithm Used

**Aho-Corasick** multi-pattern string matching (Aho & Corasick, 1975). Snort IDS uses it
for its fast-pattern engine.

- Time: O(n + m + z), where n = payload length, m = total signature length, z = matches
- Each payload character is read exactly once, whatever the number of signatures
- Matching is case-insensitive

## How It Works

**Build phase** (done once for the signature set)
1. **Trie (goto function):** insert every signature character by character. Each node is a state.
2. **Failure links (BFS):** for each state, link to the longest proper suffix of its string
   that is also a prefix in the trie (e.g. `she` → `he`). BFS guarantees shorter states are done first.
3. **Output sets:** each state outputs its own signature plus the outputs of its failure state,
   so `she` also reports `he`.

**Search phase** (per packet)
1. Start at the root and read the payload one character at a time.
2. If the current state has an edge for the character, take it (**goto**).
3. Otherwise follow **failure** links until an edge exists, or stay at the root.
4. Report every signature in the new state's output set, at position `i − len + 1`.

## Results

Output of `python sigscan.py` (11 signatures, 93 states):

| Packet | Matched signatures | Category | Verdict |
|---|---|---|---|
| `GET /login?user=admin' OR 1=1 --&pass=x HTTP/1.1` | `' or 1=1` | SQL Injection | **ALERT** |
| `POST /comment text=<SCRIPT>alert(document.cookie)</script>` | `<script>` | Cross-Site Scripting (XSS) | **ALERT** |
| `GET /download?file=../../etc/passwd HTTP/1.1` | `../`, `/etc/passwd` | Path Traversal | **ALERT** |
| `GET /index.html HTTP/1.1 Host: example.com` | – | – | CLEAN |
| `{"user": "alice", "action": "login", "remember": true}` | – | – | CLEAN |
| `POST /api/order item=book&qty=2 HTTP/1.1` | – | – | CLEAN |

All 3 attacks are detected and the 3 clean packets raise no false alarms. Overlapping matches
are all reported (`../` at positions 19 and 22, `/etc/passwd` at 24). The JavaScript demo builds
the same automaton (same states and failure links) and gives the same matches.

## Applications

- Network IDS/IPS: Snort and Suricata signature matching
- Web Application Firewalls (filtering SQLi / XSS requests)
- Antivirus scanning (ClamAV virus signatures)
- Spam and content filtering, DNA sequence search, `grep -F`

## Conclusion

Aho-Corasick turns a set of signatures into a single automaton, so a packet is scanned in
one linear pass no matter how many signatures there are. This is why it suits real-time
intrusion detection. Its limitation is that it only finds **known** exact signatures:
obfuscated or new (zero-day) attacks need other techniques.

## How to Run

| File | Command |
|---|---|
| `sigscan.py`: sample packet table + automaton states and failure links | `python sigscan.py` |
| `test_sigscan.py`: unit tests | `python -m pytest test_sigscan.py` |
| `index.html`: visual demo | open the file in a browser (works from `file://`) |

No external dependencies (pytest is only needed for the tests).
