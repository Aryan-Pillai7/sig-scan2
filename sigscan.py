"""SigScan: signature-based intrusion detection using the Aho-Corasick algorithm.

Aho-Corasick is the multi-pattern string matcher used by Snort IDS. It finds
every attack signature in a packet payload in ONE left-to-right pass,
no matter how many signatures there are.
"""
from collections import deque

# Default signature set: signature -> attack category.
SIGNATURES = {
    "' or 1=1": "SQL Injection",
    "union select": "SQL Injection",
    "drop table": "SQL Injection",
    "<script>": "Cross-Site Scripting (XSS)",
    "javascript:": "Cross-Site Scripting (XSS)",
    "onerror=": "Cross-Site Scripting (XSS)",
    "../": "Path Traversal",
    "/etc/passwd": "Path Traversal",
    "; rm -rf": "Command Injection",
    "cmd.exe": "Command Injection",
    "/bin/sh": "Command Injection",
}

# Sample packets: 3 malicious, 3 clean.
SAMPLE_PACKETS = [
    "GET /login?user=admin' OR 1=1 --&pass=x HTTP/1.1",
    "POST /comment text=<SCRIPT>alert(document.cookie)</script>",
    "GET /download?file=../../etc/passwd HTTP/1.1",
    "GET /index.html HTTP/1.1 Host: example.com",
    '{"user": "alice", "action": "login", "remember": true}',
    "POST /api/order item=book&qty=2 HTTP/1.1",
]


class AhoCorasick:
    def __init__(self):
        # State 0 is the root. For every state s:
        #   goto[s] : dict char -> next state   (the trie edges)
        #   fail[s] : failure link = state for the longest proper suffix
        #             of s's string that is also a prefix in the trie
        #   out[s]  : signatures that end when the automaton is in state s
        self.goto = [{}]
        self.fail = [0]
        self.out = [[]]

    def add(self, pattern):
        """Build step 1 (trie / goto function): insert the pattern character by character."""
        pattern = pattern.lower()  # case-insensitive matching
        state = 0
        for ch in pattern:
            if ch not in self.goto[state]:
                # No edge for this character yet: create a new state.
                self.goto.append({})
                self.fail.append(0)
                self.out.append([])
                self.goto[state][ch] = len(self.goto) - 1
            state = self.goto[state][ch]
        # The state where the pattern ends outputs that pattern.
        if pattern not in self.out[state]:
            self.out[state].append(pattern)

    def build(self):
        """Build steps 2 and 3: failure links (BFS over the trie) and output sets."""
        queue = deque()
        # Depth-1 states always fail back to the root.
        for child in self.goto[0].values():
            self.fail[child] = 0
            queue.append(child)
        # BFS visits states level by level, so shorter states (which failure
        # links point to) are always finished before longer ones.
        while queue:
            state = queue.popleft()
            for ch, child in self.goto[state].items():
                queue.append(child)
                # Failure link: follow the parent's failure links until we
                # reach a state that has an edge on the same character.
                f = self.fail[state]
                while f != 0 and ch not in self.goto[f]:
                    f = self.fail[f]
                self.fail[child] = self.goto[f].get(ch, 0)
                # Output set: signatures ending at the failure state are
                # suffixes of this state's string, so they match here too.
                self.out[child] = self.out[child] + self.out[self.fail[child]]

    def search(self, text):
        """Search phase: one pass over text, returns every (position, pattern) found."""
        matches = []
        state = 0
        for i, ch in enumerate(text):
            ch = ch.lower()
            # Mismatch: follow failure links (the input is never re-read).
            while state != 0 and ch not in self.goto[state]:
                state = self.fail[state]
            # Take the goto edge if there is one, otherwise stay at the root.
            state = self.goto[state].get(ch, 0)
            # Report every signature that ends at this character.
            for pattern in self.out[state]:
                matches.append((i - len(pattern) + 1, pattern))
        return matches


def build_scanner(signatures=SIGNATURES):
    """Insert all signatures and build the automaton once."""
    ac = AhoCorasick()
    for sig in signatures:
        ac.add(sig)
    ac.build()
    return ac


SCANNER = build_scanner()


def scan_packet(payload):
    """Return a list of matches (position, signature, category), or "CLEAN"."""
    matches = [{"position": pos, "signature": sig, "category": SIGNATURES[sig]}
               for pos, sig in SCANNER.search(payload)]
    return matches or "CLEAN"


def unique(items):
    """Remove duplicates but keep the original order."""
    return list(dict.fromkeys(items))


def print_results():
    header = f"{'Packet':<42} | {'Matched signatures':<22} | {'Category':<26} | Verdict"
    print(header)
    print("-" * len(header))
    for payload in SAMPLE_PACKETS:
        verdict = scan_packet(payload)
        shown = payload if len(payload) <= 42 else payload[:39] + "..."
        if verdict == "CLEAN":
            print(f"{shown:<42} | {'-':<22} | {'-':<26} | CLEAN")
        else:
            sigs = ", ".join(unique(m["signature"] for m in verdict))
            cats = ", ".join(unique(m["category"] for m in verdict))
            print(f"{shown:<42} | {sigs:<22} | {cats:<26} | ALERT")


def print_trie(ac):
    # Recover each state's string. Children always get larger ids than their
    # parent, so one pass in id order is enough.
    label = {0: ""}
    for state in range(len(ac.goto)):
        for ch, child in ac.goto[state].items():
            label[child] = label[state] + ch
    print(f"\nAho-Corasick automaton: {len(ac.goto)} states")
    print(f"{'State':>5}  {'String':<15} {'Failure link':<22} Output")
    for s in range(len(ac.goto)):
        f = ac.fail[s]
        print(f"{s:>5}  {label[s]!r:<15} -> {f:>3} {label[f]!r:<15} {', '.join(ac.out[s])}")


if __name__ == "__main__":
    print("SigScan: Signature-Based Intrusion Detection (Aho-Corasick)\n")
    print_results()
    print_trie(SCANNER)
