import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'malicious-ip-intel'))

from unittest.mock import patch, Mock
from virustotal_checker import check_ip

MOCK_SUCCESS = {
    "data": {
        "attributes": {
            "last_analysis_stats": {
                "malicious": 7,
                "suspicious": 1,
                "undetected": 30,
                "harmless": 20,
                "timeout": 2
            }
        }
    }
}

def _mock_response(json_data, status_code=200):
    mock = Mock()
    mock.status_code = status_code
    mock.json.return_value = json_data
    return mock

def test_returns_malicious_count():
    with patch("requests.get", return_value=_mock_response(MOCK_SUCCESS)):
        result = check_ip("1.2.3.4")
    assert result["vt_malicious"] == 7

def test_computes_total_engines():
    with patch("requests.get", return_value=_mock_response(MOCK_SUCCESS)):
        result = check_ip("1.2.3.4")
    # 7 + 1 + 30 + 20 + 2 = 60
    assert result["vt_total_engines"] == 60

def test_returns_none_on_error():
    with patch("requests.get", return_value=_mock_response({}, status_code=403)):
        result = check_ip("1.2.3.4")
    assert result["vt_malicious"] is None

def test_returns_none_on_exception():
    with patch("requests.get", side_effect=Exception("timeout")):
        result = check_ip("1.2.3.4")
    assert result["vt_malicious"] is None
