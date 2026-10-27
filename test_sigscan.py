from sigscan import AhoCorasick, scan_packet


def make(*patterns):
    ac = AhoCorasick()
    for p in patterns:
        ac.add(p)
    ac.build()
    return ac


def state_of(ac, prefix):
    """Walk the trie edges to find the state for a prefix string."""
    state = 0
    for ch in prefix:
        state = ac.goto[state][ch]
    return state


def test_single_pattern_found():
    assert make("attack").search("an attack here") == [(3, "attack")]


def test_overlapping_patterns_all_found():
    ac = make("he", "she", "his", "hers")
    found = sorted(ac.search("ushers"))
    assert found == [(1, "she"), (2, "he"), (2, "hers")]


def test_failure_links_classic_example():
    ac = make("he", "she", "his", "hers")
    expected = {
        "h": "", "he": "", "her": "", "hers": "s",
        "hi": "", "his": "s",
        "s": "", "sh": "h", "she": "he",
    }
    for prefix, fail_prefix in expected.items():
        assert ac.fail[state_of(ac, prefix)] == state_of(ac, fail_prefix), prefix
    # Output set of "she" includes "he" (inherited through its failure link).
    assert sorted(ac.out[state_of(ac, "she")]) == ["he", "she"]


def test_case_insensitive():
    ac = make("Union Select")
    assert ac.search("id=1 UNION SELECT pw") == [(5, "union select")]
    assert scan_packet("<ScRiPt>")[0]["category"] == "Cross-Site Scripting (XSS)"


def test_clean_payload():
    assert scan_packet("GET /index.html HTTP/1.1 Host: example.com") == "CLEAN"
    assert make("he", "she").search("xyz") == []


def test_positions_are_correct():
    payload = "GET /download?file=../../etc/passwd"
    result = scan_packet(payload)
    for m in result:
        sig = m["signature"]
        assert payload[m["position"]:m["position"] + len(sig)].lower() == sig
    assert [(m["position"], m["signature"]) for m in result] == [
        (19, "../"), (22, "../"), (24, "/etc/passwd")]
