import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'malicious-ip-intel'))

from classifier import classify, SAFE, SUSPICIOUS, MALICIOUS, UNKNOWN

def test_malicious_by_abuse_score():
    assert classify(abuse_score=90, vt_malicious=0) == MALICIOUS

def test_malicious_by_vt_engines():
    assert classify(abuse_score=0, vt_malicious=6) == MALICIOUS

def test_malicious_both_triggers():
    assert classify(abuse_score=85, vt_malicious=10) == MALICIOUS

def test_suspicious_by_abuse_score():
    assert classify(abuse_score=50, vt_malicious=0) == SUSPICIOUS

def test_suspicious_by_vt_engines():
    assert classify(abuse_score=0, vt_malicious=3) == SUSPICIOUS

def test_safe_both_clean():
    assert classify(abuse_score=5, vt_malicious=0) == SAFE

def test_unknown_both_none():
    assert classify(abuse_score=None, vt_malicious=None) == UNKNOWN

def test_partial_failure_abuse_only():
    # VT failed (None), abuse score is malicious → Malicious
    assert classify(abuse_score=90, vt_malicious=None) == MALICIOUS

def test_partial_failure_vt_only():
    # Abuse failed (None), VT is suspicious → Suspicious
    assert classify(abuse_score=None, vt_malicious=3) == SUSPICIOUS

def test_boundary_abuse_malicious():
    assert classify(abuse_score=80, vt_malicious=0) == MALICIOUS

def test_boundary_abuse_suspicious():
    assert classify(abuse_score=20, vt_malicious=0) == SUSPICIOUS

def test_boundary_abuse_safe():
    assert classify(abuse_score=19, vt_malicious=0) == SAFE

def test_boundary_vt_malicious():
    assert classify(abuse_score=0, vt_malicious=5) == MALICIOUS

def test_boundary_vt_suspicious_upper():
    assert classify(abuse_score=0, vt_malicious=4) == SUSPICIOUS

def test_boundary_vt_suspicious_floor():
    assert classify(abuse_score=0, vt_malicious=1) == SUSPICIOUS

def test_boundary_vt_safe():
    assert classify(abuse_score=0, vt_malicious=0) == SAFE
