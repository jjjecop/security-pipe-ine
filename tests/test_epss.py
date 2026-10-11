from epss import parse_epss_response


def test_parse_epss_response_reads_scores_as_float():
    data = {
        "status": "OK",
        "data": [
            {"cve": "CVE-2021-44906", "epss": "0.045810000", "percentile": "0.914080000"},
            {"cve": "CVE-2021-23337", "epss": "0.213330000", "percentile": "0.975530000"},
        ],
    }
    assert parse_epss_response(data) == {"CVE-2021-44906": 0.04581, "CVE-2021-23337": 0.21333}


def test_parse_epss_response_handles_no_data():
    assert parse_epss_response({"status": "OK", "data": []}) == {}
    assert parse_epss_response({"status": "OK"}) == {}
