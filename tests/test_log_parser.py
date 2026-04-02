import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'malicious-ip-intel'))

from log_parser import extract_ips

def test_extracts_public_ip():
    log = '8.8.8.8 - - [16/Mar/2026] "GET / HTTP/1.1" 200 100'
    assert "8.8.8.8" in extract_ips(log)

def test_deduplicates_ips():
    log = "8.8.8.8 - - [t] \"GET /\" 200 1\n8.8.8.8 - - [t] \"GET /\" 200 1"
    result = extract_ips(log)
    assert result.count("8.8.8.8") == 1

def test_skips_private_192_168():
    log = '192.168.1.10 - - [t] "GET /" 200 1'
    assert "192.168.1.10" not in extract_ips(log)

def test_skips_private_10():
    log = '10.0.0.5 - - [t] "GET /" 200 1'
    assert "10.0.0.5" not in extract_ips(log)

def test_skips_private_172_16():
    log = '172.16.0.1 - - [t] "GET /" 200 1'
    assert "172.16.0.1" not in extract_ips(log)

def test_skips_private_172_31():
    log = '172.31.255.255 - - [t] "GET /" 200 1'
    assert "172.31.255.255" not in extract_ips(log)

def test_skips_loopback_127():
    log = '127.0.0.1 - - [t] "GET /" 200 1'
    assert "127.0.0.1" not in extract_ips(log)

def test_skips_link_local_169_254():
    log = '169.254.1.1 - - [t] "GET /" 200 1'
    assert "169.254.1.1" not in extract_ips(log)

def test_returns_list():
    log = '1.1.1.1 - - [t] "GET /" 200 1'
    result = extract_ips(log)
    assert isinstance(result, list)

def test_empty_log_returns_empty():
    assert extract_ips("") == []
