from app.parsing import format_hash_rate_mhs


def test_format_hash_rate_ph():
    s = format_hash_rate_mhs(63562856216.49001)
    assert "PH/s" in s
    assert "63.5628562165" in s


def test_format_zero():
    assert format_hash_rate_mhs(0) == "0 MH/s"


def test_format_none():
    assert format_hash_rate_mhs(None) == "\u2014"
