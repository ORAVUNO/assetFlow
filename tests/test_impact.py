"""Tests for object / member effective-access impact analysis."""

from assetflow import impact


def _rules():
    cols = [{"name": n} for n in ["host.name", "rule.uid", "rule.name", "src_zone",
                                  "source", "dst_zone", "destination", "service", "action", "disabled"]]
    rows = [
        # DB-Servers is a destination reachable by App-Tier on tcp/443
        ["FW-A", "r1", "app→db", "app", "App-Tier", "db", "DB-Servers", "tcp/443", "accept", "False"],
        # Web-Servers is a source that can reach the Internet on tcp/80
        ["FW-A", "r2", "web out", "dmz", "Web-Servers", "out", "Internet", "tcp/80", "accept", "False"],
        # a disabled rule referencing DB-Servers must be ignored
        ["FW-A", "r3", "old", "x", "Legacy", "y", "DB-Servers", "tcp/22", "accept", "True"],
        # different device
        ["FW-B", "r9", "other", "a", "DB-Servers", "b", "X", "tcp/1", "accept", "False"],
    ]
    return {"columns": cols, "rows": rows}


def test_object_impact_splits_by_side_and_ignores_disabled():
    imp = impact.object_impact("DB-Servers", _rules())
    src_uids = {e["rule.uid"] for e in imp["as_source"]}
    dst_uids = {e["rule.uid"] for e in imp["as_destination"]}
    assert dst_uids == {"r1"}            # r1 (destination), r3 disabled excluded
    assert src_uids == {"r9"}            # DB-Servers is a source on FW-B's r9
    assert imp["rule_count"] == 2


def test_object_impact_device_scope():
    imp = impact.object_impact("DB-Servers", _rules(), device="FW-A")
    assert {e["rule.uid"] for e in imp["as_destination"]} == {"r1"}
    assert imp["as_source"] == []        # the FW-B source rule is out of scope


def test_member_sentences_frame_the_new_member_and_expose_reachers():
    imp = impact.object_impact("DB-Servers", _rules(), device="FW-A")
    sents = impact.member_sentences("DB-Servers", imp, member="10.9.9.9")
    # DB-Servers is a destination here -> the member becomes reachable by App-Tier.
    s = [x for x in sents if x["direction"] == "reachable by"][0]
    assert s["text"] == "App-Tier → 10.9.9.9 : tcp/443 (accept)"
    assert s["reachable_by"] == "App-Tier"   # the exposure — who can now reach it


def test_member_sentences_source_side_shows_what_it_can_reach():
    imp = impact.object_impact("Web-Servers", _rules(), device="FW-A")
    sents = impact.member_sentences("Web-Servers", imp, member="10.1.1.9")
    s = [x for x in sents if x["direction"] == "can reach"][0]
    assert s["text"] == "10.1.1.9 → Internet : tcp/80 (accept)"


def test_no_reference_yields_no_access():
    imp = impact.object_impact("Unused-Object", _rules())
    assert imp["rule_count"] == 0
    assert impact.member_sentences("Unused-Object", imp, "10.0.0.1") == []


def test_token_match_avoids_substring_false_positives():
    # "DB" must not match "DB-Servers"
    imp = impact.object_impact("DB", _rules())
    assert imp["rule_count"] == 0
