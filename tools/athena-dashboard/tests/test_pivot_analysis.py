"""B78b: cross-host pivot must report honestly, never a silent zero.

The pivot query depends on Neo4j inputs (Host.compromised + NETWORK_ACCESS/
CONNECTS_TO edges) that nothing currently writes. When those inputs are absent,
the analysis did not run — that must be distinguishable from "no pivot paths
found". These tests pin the pure decision helper (Neo4j-free).
"""
import pytest

from server import _pivot_analysis_status


def test_unavailable_when_no_compromised_hosts_and_no_edges():
    status, reason = _pivot_analysis_status(
        compromised_count=0, reachability_edge_count=0, pivot_links_count=0)
    assert status == "unavailable"
    assert reason  # non-empty explanation, not a silent zero
    assert "not computed" in reason.lower() or "not populated" in reason.lower()


def test_unavailable_when_compromised_but_no_edges():
    # The query needs an outgoing reachability edge; without one it can't
    # produce a path, so a 0 is "not computed", not "no lateral movement".
    status, reason = _pivot_analysis_status(
        compromised_count=2, reachability_edge_count=0, pivot_links_count=0)
    assert status == "unavailable"
    assert reason


def test_unavailable_when_edges_but_no_compromised():
    status, reason = _pivot_analysis_status(
        compromised_count=0, reachability_edge_count=5, pivot_links_count=0)
    assert status == "unavailable"
    assert reason


def test_available_when_both_inputs_present_and_zero_pivots():
    # Both inputs exist and the query genuinely found nothing — a real 0.
    status, reason = _pivot_analysis_status(
        compromised_count=1, reachability_edge_count=3, pivot_links_count=0)
    assert status == "available"
    assert reason is None


def test_available_when_pivots_actually_found():
    status, reason = _pivot_analysis_status(
        compromised_count=1, reachability_edge_count=3, pivot_links_count=2)
    assert status == "available"
    assert reason is None


def test_pivots_found_wins_even_if_input_counts_are_zero():
    # Guards I1: if pivots were found, status must never contradict the result
    # even if a later re-probe of the inputs failed to recount them.
    status, reason = _pivot_analysis_status(
        compromised_count=0, reachability_edge_count=0, pivot_links_count=2)
    assert status == "available"
    assert reason is None


@pytest.mark.asyncio
async def test_report_data_always_carries_pivot_status(client):
    """The client deliverable must never omit cross-host pivot status.

    With no Neo4j in the test env, the probe can't run, so the honest default
    is 'unavailable' (not computed) — never a silent absence.
    """
    rd = (await client.get("/api/engagements/eng-pivot-rd/report-data")).json()
    assert "cross_host_pivot" in rd
    assert rd["cross_host_pivot"]["status"] == "unavailable"
    assert rd["cross_host_pivot"]["reason"]
