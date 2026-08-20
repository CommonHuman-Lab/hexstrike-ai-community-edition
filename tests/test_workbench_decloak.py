"""
tests/test_workbench_decloak.py

Pure-Python unit tests for server_core/workbench/decloak.py — the
auto-detect-and-recursively-decode engine backing the Workbench's
Decloak mode. No subprocess, no Flask, no network calls.
"""

from backend.server_core.workbench.decloak import _score, run_decloak


class TestRunDecloak:
    def test_user_example_hex_then_base64_to_plaintext(self):
        result = run_decloak("564739775532566a636d56305132396b5a513d3d")
        assert result["output"] == "TopSecretCode"
        assert result["stopped_reason"] == "plaintext"
        assert [s["operation_id"] for s in result["steps"]] == ["hex", "base64"]
        assert result["steps"][0]["output"] == "VG9wU2VjcmV0Q29kZQ=="

    def test_already_plaintext_returns_unchanged(self):
        result = run_decloak("hello world")
        assert result["steps"] == []
        assert result["output"] == "hello world"
        assert result["stopped_reason"] == "plaintext"

    def test_max_depth_reached(self):
        result = run_decloak("564739775532566a636d56305132396b5a513d3d", max_depth=1)
        assert result["stopped_reason"] == "max_depth"
        assert len(result["steps"]) == 1

    def test_terminal_stop_on_hash_identify_before_hex_decode(self):
        md5_like = "5d41402abc4b2a76b9719d911017c592"
        result = run_decloak(md5_like)
        assert result["steps"][0]["operation_id"] == "hash_identify"
        assert result["output"] == result["steps"][0]["output"]
        assert result["stopped_reason"] == "terminal"

    def test_terminal_output_matches_last_step_not_stale_input(self):
        jwt = (
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
            "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0."
            "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        )
        result = run_decloak(jwt)
        assert result["output"] != jwt
        assert result["output"] == result["steps"][-1]["output"]
        assert "John Doe" in result["output"]

    def test_uniform_hash_bytes_not_falsely_xord(self):
        sha256_like = "a" * 64
        result = run_decloak(sha256_like)
        assert result["steps"][0]["operation_id"] == "hash_identify"
        assert result["stopped_reason"] == "terminal"

    def test_plain_english_not_falsely_rot13d(self):
        result = run_decloak("the quick brown fox jumps over the lazy dog")
        assert result["steps"] == []

    def test_decimal_charcode_to_plaintext(self):
        result = run_decloak("72 101 108 108 111")
        assert result["output"] == "Hello"
        assert [s["operation_id"] for s in result["steps"]] == ["charcode_convert"]

    def test_punycode_domain_to_unicode(self):
        result = run_decloak("xn--mnchen-3ya.de")
        assert result["output"] == "münchen.de"
        assert [s["operation_id"] for s in result["steps"]] == ["punycode"]

    def test_basic_auth_header_to_userpass(self):
        result = run_decloak("Basic dXNlcjpwYXNz")
        assert result["output"] == "user:pass"
        assert [s["operation_id"] for s in result["steps"]] == ["basic_auth"]

    def test_nested_base64_of_binary_charcode(self):
        import base64
        nested = base64.b64encode(b"01001000 01101001").decode()
        result = run_decloak(nested)
        assert result["output"] == "Hi"
        assert [s["operation_id"] for s in result["steps"]] == ["base64", "charcode_convert"]

    def test_base58_to_plaintext(self):
        result = run_decloak("72k1xXWG59fYdzSNoA")
        assert result["output"] == "Hello, World!"
        assert [s["operation_id"] for s in result["steps"]] == ["base58"]

    def test_quoted_printable_to_plaintext(self):
        result = run_decloak("caf=C3=A9 r=C3=A9sum=C3=A9")
        assert result["output"] == "café résumé"
        assert [s["operation_id"] for s in result["steps"]] == ["quoted_printable"]

    def test_uuencoded_block_to_plaintext(self):
        from backend.server_core.workbench.registry import get_operation
        encoded = get_operation("uuencode").run({"input": "Hello, uuencode!"})["output"]
        result = run_decloak(encoded)
        assert result["output"] == "Hello, uuencode!"
        assert [s["operation_id"] for s in result["steps"]] == ["uuencode"]

    def test_base64url_to_plaintext(self):
        from backend.server_core.workbench.registry import get_operation
        encoded = get_operation("base64url").run({"input": "subjects?x=1&y=2", "mode": "encode"})["output"]
        result = run_decloak(encoded)
        assert result["output"] == "subjects?x=1&y=2"
        assert [s["operation_id"] for s in result["steps"]] == ["base64url"]

    def test_utf7_to_plaintext(self):
        result = run_decloak("Hi Mom +Jjo!")
        assert result["output"] == "Hi Mom ☺!"
        assert [s["operation_id"] for s in result["steps"]] == ["utf7"]

    def test_xor_single_byte_to_plaintext(self):
        from backend.server_core.workbench.registry import get_operation
        hexed = get_operation("xor_cipher").run({"input": "Secret message here", "key": "k"})["output"]
        result = run_decloak(hexed)
        assert result["output"] == "Secret message here"
        assert [s["operation_id"] for s in result["steps"]] == ["xor_cipher"]

    def test_atbash_wins_over_rot13_when_both_score_plausible(self):
        result = run_decloak("Nvvg nv zg gsv low yirwtv glmrtsg zg mrmv")
        assert result["output"] == "Meet me at the old bridge tonight at nine"
        assert [s["operation_id"] for s in result["steps"]] == ["atbash"]

    def test_coincidental_query_string_equals_not_mangled_by_quoted_printable(self):
        result = run_decloak("q=eagle&loc=north gate?")
        assert result["steps"] == []
        assert result["output"] == "q=eagle&loc=north gate?"


class TestScore:
    def test_empty_string_scores_zero(self):
        assert _score("") == 0.0

    def test_readable_text_scores_higher_than_control_bytes(self):
        assert _score("the quick brown fox") > _score("\x01\x02\x03\x04\x05")
