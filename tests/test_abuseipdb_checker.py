import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'malicious-ip-intel'))

from unittest.mock import patch, Mock
from abuseipdb_checker import check_ip

MOCK_SUCCESS = {
    "data": {
        "abuseConfidenceScore": 75,
        "totalReports": 12,
        "countryCode": "RU",
        "isp": "Some ISP"
    }
}

def _mock_response(json_data, status_code=200):
    mock = Mock()
    mock.status_code = status_code
    mock.json.return_value = json_data
    return mock

def test_returns_expected_fields():
    with patch("requests.get", return_value=_mock_response(MOCK_SUCCESS)):
        result = check_ip("1.2.3.4")
    assert result["abuse_score"] == 75
    assert result["total_reports"] == 12
    assert result["country"] == "RU"
    assert result["isp"] == "Some ISP"

def test_returns_none_on_error():
    with patch("requests.get", return_value=_mock_response({}, status_code=500)):
        result = check_ip("1.2.3.4")
    assert result["abuse_score"] is None

def test_returns_none_on_exception():
    with patch("requests.get", side_effect=Exception("timeout")):
        result = check_ip("1.2.3.4")
    assert result["abuse_score"] is None
