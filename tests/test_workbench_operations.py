"""
tests/test_workbench_operations.py

Correctness tests for each Workbench operation's run() function — encoding,
hashing, ciphers, compression, and text utilities. Pure-Python, no subprocess,
no Flask, no network calls, so these are safe/cheap to run on every commit.
"""

import pytest

from backend.server_core.workbench.registry import get_operation


def run(op_id: str, **params) -> dict:
    op = get_operation(op_id)
    assert op is not None, f"operation {op_id!r} not found in registry"
    return op.run(params)


def decloak_try(op_id: str, text: str):
    op = get_operation(op_id)
    assert op is not None, f"operation {op_id!r} not found in registry"
    assert op.decloak_try is not None, f"operation {op_id!r} has no decloak_try"
    return op.decloak_try(text)


# ---------------------------------------------------------------------------
# encoding
# ---------------------------------------------------------------------------

class TestBase64:
    def test_encode(self):
        assert run("base64", input="hello", mode="encode")["output"] == "aGVsbG8="

    def test_decode(self):
        assert run("base64", input="aGVsbG8=", mode="decode")["output"] == "hello"

    def test_default_mode_is_encode(self):
        assert run("base64", input="hello") == run("base64", input="hello", mode="encode")

    def test_decode_invalid_raises(self):
        with pytest.raises(ValueError):
            run("base64", input="not valid base64!!!", mode="decode")

    def test_unsupported_mode_raises(self):
        with pytest.raises(ValueError):
            run("base64", input="hello", mode="rot13")

    def test_round_trip(self):
        encoded = run("base64", input="round trip me", mode="encode")["output"]
        assert run("base64", input=encoded, mode="decode")["output"] == "round trip me"

    def test_decloak_try_matches_valid_base64(self):
        assert decloak_try("base64", "VG9wU2VjcmV0Q29kZQ==") == "TopSecretCode"

    def test_decloak_try_none_on_non_base64(self):
        assert decloak_try("base64", "not base64 at all!!!") is None

    def test_decloak_try_none_on_too_short(self):
        assert decloak_try("base64", "abc") is None


class TestBase64Url:
    def test_round_trip(self):
        encoded = run("base64url", input="subjects?x=1&y=2", mode="encode")["output"]
        assert run("base64url", input=encoded, mode="decode")["output"] == "subjects?x=1&y=2"

    def test_encode_uses_dash_underscore_alphabet(self):
        assert run("base64url", input="subjects?x=1&y=2", mode="encode")["output"] == "c3ViamVjdHM_eD0xJnk9Mg=="

    def test_default_mode_is_encode(self):
        assert run("base64url", input="hello") == run("base64url", input="hello", mode="encode")

    def test_decode_invalid_raises(self):
        with pytest.raises(ValueError):
            run("base64url", input="not valid!!!", mode="decode")

    def test_decloak_try_matches_dash_underscore_base64(self):
        encoded = run("base64url", input="subjects?x=1&y=2", mode="encode")["output"]
        assert decloak_try("base64url", encoded) == "subjects?x=1&y=2"

    def test_decloak_try_none_without_dash_or_underscore(self):
        assert decloak_try("base64url", "VG9wU2VjcmV0Q29kZQ==") is None


class TestUtf7:
    def test_round_trip(self):
        encoded = run("utf7", input="Hi Mom ☺!", mode="encode")["output"]
        assert run("utf7", input=encoded, mode="decode")["output"] == "Hi Mom ☺!"

    def test_encode_known_vector(self):
        assert run("utf7", input="Hi Mom ☺!", mode="encode")["output"] == "Hi Mom +Jjo!"

    def test_default_mode_is_encode(self):
        assert run("utf7", input="hello") == run("utf7", input="hello", mode="encode")

    def test_decloak_try_matches_shift_sequence(self):
        assert decloak_try("utf7", "Hi Mom +Jjo!") == "Hi Mom ☺!"

    def test_decloak_try_none_without_plus(self):
        assert decloak_try("utf7", "plain ascii text") is None


class TestBase32:
    def test_encode(self):
        assert run("base32", input="hello", mode="encode")["output"] == "NBSWY3DP"

    def test_decode(self):
        assert run("base32", input="NBSWY3DP", mode="decode")["output"] == "hello"

    def test_decode_invalid_raises(self):
        with pytest.raises(ValueError):
            run("base32", input="!!!not-valid!!!", mode="decode")

    def test_round_trip(self):
        encoded = run("base32", input="round trip me", mode="encode")["output"]
        assert run("base32", input=encoded, mode="decode")["output"] == "round trip me"


class TestHex:
    def test_encode(self):
        assert run("hex", input="hi", mode="encode")["output"] == "6869"

    def test_decode(self):
        assert run("hex", input="6869", mode="decode")["output"] == "hi"

    def test_decode_ignores_whitespace(self):
        assert run("hex", input="68 69\n", mode="decode")["output"] == "hi"

    def test_decode_invalid_raises(self):
        with pytest.raises(ValueError):
            run("hex", input="zz", mode="decode")

    def test_decloak_try_matches_valid_hex(self):
        assert decloak_try("hex", "68656c6c6f21") == "hello!"

    def test_decloak_try_none_on_non_hex(self):
        assert decloak_try("hex", "not hex at all!!!") is None

    def test_decloak_try_none_on_too_short(self):
        assert decloak_try("hex", "6869") is None


class TestUrlEncoding:
    def test_encode_default_leaves_slash(self):
        assert run("url_encoding", input="a b/c", mode="encode")["output"] == "a%20b/c"

    def test_encode_all_encodes_slash(self):
        result = run("url_encoding", input="a b/c", mode="encode", encode_all="true")["output"]
        assert result == "a%20b%2Fc"

    def test_decode(self):
        assert run("url_encoding", input="a%20b%2Fc", mode="decode")["output"] == "a b/c"


class TestHtmlEntities:
    def test_encode(self):
        result = run("html_entities", input='<a href="x">&Test</a>', mode="encode")["output"]
        assert result == "&lt;a href=&quot;x&quot;&gt;&amp;Test&lt;/a&gt;"

    def test_decode(self):
        assert run("html_entities", input="&lt;a&gt;&amp;", mode="decode")["output"] == "<a>&"

    def test_round_trip(self):
        original = '<script>alert("hi")</script>'
        encoded = run("html_entities", input=original, mode="encode")["output"]
        assert run("html_entities", input=encoded, mode="decode")["output"] == original


class TestBase85:
    def test_round_trip(self):
        encoded = run("base85", input="round trip me", mode="encode")["output"]
        assert run("base85", input=encoded, mode="decode")["output"] == "round trip me"

    def test_default_mode_is_encode(self):
        assert run("base85", input="hello") == run("base85", input="hello", mode="encode")

    def test_decode_invalid_raises(self):
        with pytest.raises(ValueError):
            run("base85", input="\x01\x02not valid", mode="decode")


class TestBase58:
    def test_round_trip(self):
        encoded = run("base58", input="Hello, World!", mode="encode")["output"]
        assert run("base58", input=encoded, mode="decode")["output"] == "Hello, World!"

    def test_encode_known_vector(self):
        assert run("base58", input="Hello, World!", mode="encode")["output"] == "72k1xXWG59fYdzSNoA"

    def test_default_mode_is_encode(self):
        assert run("base58", input="hello") == run("base58", input="hello", mode="encode")

    def test_decode_invalid_char_raises(self):
        with pytest.raises(ValueError):
            run("base58", input="0OIl", mode="decode")

    def test_decloak_try_matches_valid_base58(self):
        assert decloak_try("base58", "72k1xXWG59fYdzSNoA") == "Hello, World!"

    def test_decloak_try_none_on_short_word(self):
        assert decloak_try("base58", "cat") is None


class TestBase45:
    def test_round_trip(self):
        encoded = run("base45", input="Hello!!", mode="encode")["output"]
        assert run("base45", input=encoded, mode="decode")["output"] == "Hello!!"

    def test_encode_known_vector(self):
        assert run("base45", input="AB", mode="encode")["output"] == "BB8"

    def test_default_mode_is_encode(self):
        assert run("base45", input="hello") == run("base45", input="hello", mode="encode")

    def test_decode_invalid_char_raises(self):
        with pytest.raises(ValueError):
            run("base45", input="!!!", mode="decode")

    def test_decloak_try_matches_valid_base45(self):
        encoded = run("base45", input="Hello, Base45!", mode="encode")["output"]
        assert decloak_try("base45", encoded) == "Hello, Base45!"

    def test_decloak_try_none_on_too_short(self):
        assert decloak_try("base45", "AB") is None


class TestMorseCode:
    def test_encode(self):
        assert run("morse_code", input="SOS")["output"] == "... --- ..."

    def test_round_trip(self):
        encoded = run("morse_code", input="HELLO WORLD")["output"]
        assert run("morse_code", input=encoded, mode="decode")["output"] == "HELLO WORLD"

    def test_encode_unmapped_char_raises(self):
        with pytest.raises(ValueError):
            run("morse_code", input="hello~world")

    def test_decode_invalid_token_raises(self):
        with pytest.raises(ValueError):
            run("morse_code", input="......", mode="decode")

    def test_decloak_try_matches_morse(self):
        assert decloak_try("morse_code", "... --- ... / .... . .-.. .-.. ---") == "SOS HELLO"

    def test_decloak_try_none_on_plain_text(self):
        assert decloak_try("morse_code", "hello world") is None


class TestQuotedPrintable:
    def test_round_trip(self):
        encoded = run("quoted_printable", input="café résumé", mode="encode")["output"]
        assert run("quoted_printable", input=encoded, mode="decode")["output"] == "café résumé"

    def test_encode_known_vector(self):
        assert run("quoted_printable", input="café", mode="encode")["output"] == "caf=C3=A9"

    def test_default_mode_is_encode(self):
        assert run("quoted_printable", input="hello") == run("quoted_printable", input="hello", mode="encode")

    def test_decloak_try_matches_escaped_text(self):
        assert decloak_try("quoted_printable", "caf=C3=A9 r=C3=A9sum=C3=A9") == "café résumé"

    def test_decloak_try_none_without_escapes(self):
        assert decloak_try("quoted_printable", "plain text, no escapes here") is None

    def test_decloak_try_none_on_coincidental_equals_hex_pair(self):
        assert decloak_try("quoted_printable", "q=eagle&loc=north gate?") is None


class TestUuencode:
    def test_round_trip(self):
        encoded = run("uuencode", input="Cat")["output"]
        assert run("uuencode", input=encoded, mode="decode")["output"] == "Cat"

    def test_default_mode_is_encode(self):
        assert run("uuencode", input="hello") == run("uuencode", input="hello", mode="encode")

    def test_decode_missing_header_raises(self):
        with pytest.raises(ValueError):
            run("uuencode", input="not uuencoded data", mode="decode")

    def test_decloak_try_matches_uuencoded_block(self):
        encoded = run("uuencode", input="Hello, uuencode!")["output"]
        assert decloak_try("uuencode", encoded) == "Hello, uuencode!"

    def test_decloak_try_none_without_begin_header(self):
        assert decloak_try("uuencode", "just some text") is None


class TestPunycode:
    def test_decode(self):
        assert run("punycode", input="xn--mnchen-3ya.de", mode="decode")["output"] == "münchen.de"

    def test_encode(self):
        assert run("punycode", input="münchen.de", mode="encode")["output"] == "xn--mnchen-3ya.de"

    def test_default_mode_is_decode(self):
        assert run("punycode", input="xn--mnchen-3ya.de") == run("punycode", input="xn--mnchen-3ya.de", mode="decode")

    def test_label_too_long_raises(self):
        with pytest.raises(ValueError):
            run("punycode", input="a" * 70 + ".com", mode="encode")

    def test_non_ascii_decode_input_raises(self):
        with pytest.raises(ValueError):
            run("punycode", input="xn--é.com", mode="decode")

    def test_empty_input_raises(self):
        with pytest.raises(ValueError):
            run("punycode", input="")

    def test_decloak_try_matches_xn_domain(self):
        assert decloak_try("punycode", "xn--mnchen-3ya.de") == "münchen.de"

    def test_decloak_try_none_on_ordinary_domain(self):
        assert decloak_try("punycode", "example.com") is None


class TestCharcodeConvert:
    def test_to_charcode_decimal(self):
        assert run("charcode_convert", input="AB", mode="to_charcode")["output"] == "65 66"

    def test_to_charcode_hex(self):
        assert run("charcode_convert", input="AB", mode="to_charcode", base="hexadecimal")["output"] == "41 42"

    def test_round_trip(self):
        codes = run("charcode_convert", input="hello!", mode="to_charcode")["output"]
        assert run("charcode_convert", input=codes, mode="from_charcode")["output"] == "hello!"

    def test_custom_delimiter(self):
        codes = run("charcode_convert", input="AB", mode="to_charcode", delimiter=",")["output"]
        assert codes == "65,66"
        assert run("charcode_convert", input=codes, mode="from_charcode", delimiter=",")["output"] == "AB"

    def test_from_charcode_empty_raises(self):
        with pytest.raises(ValueError):
            run("charcode_convert", input="", mode="from_charcode")

    def test_from_charcode_invalid_token_raises(self):
        with pytest.raises(ValueError):
            run("charcode_convert", input="65 zz", mode="from_charcode")

    def test_to_charcode_binary(self):
        assert run("charcode_convert", input="AB", mode="to_charcode", base="binary")["output"] == "01000001 01000010"

    def test_binary_round_trip(self):
        codes = run("charcode_convert", input="hello!", mode="to_charcode", base="binary")["output"]
        assert run("charcode_convert", input=codes, mode="from_charcode", base="binary")["output"] == "hello!"

    def test_decloak_try_matches_decimal_charcode(self):
        assert decloak_try("charcode_convert", "72 101 108 108 111") == "Hello"

    def test_decloak_try_matches_binary_charcode(self):
        assert decloak_try("charcode_convert", "01001000 01100101 01101100 01101100 01101111") == "Hello"

    def test_decloak_try_none_on_single_number(self):
        assert decloak_try("charcode_convert", "72") is None

    def test_decloak_try_none_on_ordinary_sentence(self):
        assert decloak_try("charcode_convert", "the quick brown fox") is None


# ---------------------------------------------------------------------------
# hashing
# ---------------------------------------------------------------------------

class TestHashDigest:
    def test_md5_known_vector(self):
        assert run("hash_digest", input="hello", algorithm="md5")["output"] == "5d41402abc4b2a76b9719d911017c592"

    def test_sha256_known_vector(self):
        expected = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        assert run("hash_digest", input="hello", algorithm="sha256")["output"] == expected

    def test_default_algorithm_is_sha256(self):
        assert run("hash_digest", input="hello") == run("hash_digest", input="hello", algorithm="sha256")

    def test_unsupported_algorithm_raises(self):
        with pytest.raises(ValueError):
            run("hash_digest", input="hello", algorithm="md6")


class TestHmacDigest:
    def test_known_vector(self):
        # HMAC-SHA256("key", "The quick brown fox jumps over the lazy dog")
        expected = "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"
        result = run(
            "hmac_digest",
            input="The quick brown fox jumps over the lazy dog",
            key="key",
            algorithm="sha256",
        )["output"]
        assert result == expected

    def test_different_keys_produce_different_digests(self):
        a = run("hmac_digest", input="msg", key="key1")["output"]
        b = run("hmac_digest", input="msg", key="key2")["output"]
        assert a != b

    def test_unsupported_algorithm_raises(self):
        with pytest.raises(ValueError):
            run("hmac_digest", input="msg", key="k", algorithm="md6")


class TestChecksum:
    def test_crc32_matches_zlib(self):
        import zlib

        expected = f"{zlib.crc32(b'hello'):08x}"
        assert run("checksum", input="hello", algorithm="crc32")["output"] == expected

    def test_adler32_matches_zlib(self):
        import zlib

        expected = f"{zlib.adler32(b'hello'):08x}"
        assert run("checksum", input="hello", algorithm="adler32")["output"] == expected

    def test_default_algorithm_is_crc32(self):
        assert run("checksum", input="hello") == run("checksum", input="hello", algorithm="crc32")

    def test_unsupported_algorithm_raises(self):
        with pytest.raises(ValueError):
            run("checksum", input="hello", algorithm="md5")


# ---------------------------------------------------------------------------
# ciphers
# ---------------------------------------------------------------------------

class TestRot13:
    def test_encode(self):
        assert run("rot13", input="hello")["output"] == "uryyb"

    def test_self_inverse(self):
        assert run("rot13", input=run("rot13", input="hello")["output"])["output"] == "hello"

    def test_decloak_try_never_returns_none_for_non_empty_input(self):
        assert decloak_try("rot13", "uryyb jbeyq") == "hello world"

    def test_decloak_try_none_on_empty_input(self):
        assert decloak_try("rot13", "   ") is None


class TestCaesarCipher:
    def test_default_shift(self):
        assert run("caesar_cipher", input="abc")["output"] == "def"

    def test_negative_shift_decodes(self):
        encoded = run("caesar_cipher", input="hello", shift=5)["output"]
        assert run("caesar_cipher", input=encoded, shift=-5)["output"] == "hello"

    def test_non_alpha_passes_through(self):
        assert run("caesar_cipher", input="a-1!", shift=1)["output"] == "b-1!"

    def test_invalid_shift_raises(self):
        with pytest.raises(ValueError):
            run("caesar_cipher", input="abc", shift="not-a-number")


class TestXorCipher:
    def test_empty_key_raises(self):
        with pytest.raises(ValueError):
            run("xor_cipher", input="abc", key="")

    def test_round_trip_via_hex_decode(self):
        # xor_cipher outputs hex; XORing again with the same key recovers the
        # original bytes once the hex is decoded back to raw bytes.
        hex_out = run("xor_cipher", input="secret message", key="k3y")["output"]
        raw = bytes.fromhex(hex_out)
        key_bytes = b"k3y"
        recovered = bytes(b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(raw))
        assert recovered.decode("utf-8") == "secret message"

    def test_decloak_try_recovers_single_byte_key(self):
        hexed = run("xor_cipher", input="Secret message here", key="k")["output"]
        assert decloak_try("xor_cipher", hexed) == "Secret message here"

    def test_decloak_try_none_on_non_hex(self):
        assert decloak_try("xor_cipher", "not hex at all!!!") is None

    def test_decloak_try_none_on_uniform_hash_bytes(self):
        assert decloak_try("xor_cipher", "a" * 64) is None

    def test_decloak_try_none_on_plain_hex_of_text(self):
        hexed = run("hex", input="hello world", mode="encode")["output"]
        assert decloak_try("xor_cipher", hexed) is None


class TestRot47:
    def test_encode(self):
        assert run("rot47", input="Hello, World!")["output"] == "w6==@[ (@C=5P"

    def test_self_inverse(self):
        encoded = run("rot47", input="Hello, World!")["output"]
        assert run("rot47", input=encoded)["output"] == "Hello, World!"

    def test_decloak_try_never_returns_none_for_non_empty_input(self):
        assert decloak_try("rot47", "w6==@[ (@C=5P") == "Hello, World!"

    def test_decloak_try_none_on_empty_input(self):
        assert decloak_try("rot47", "   ") is None


class TestAtbash:
    def test_encode(self):
        assert run("atbash", input="Hello, World!")["output"] == "Svool, Dliow!"

    def test_self_inverse(self):
        encoded = run("atbash", input="Hello, World!")["output"]
        assert run("atbash", input=encoded)["output"] == "Hello, World!"

    def test_decloak_try_never_returns_none_for_non_empty_input(self):
        assert decloak_try("atbash", "Svool, Dliow!") == "Hello, World!"

    def test_decloak_try_none_on_empty_input(self):
        assert decloak_try("atbash", "   ") is None


class TestVigenereCipher:
    def test_known_vector(self):
        assert run("vigenere_cipher", input="ATTACKATDAWN", key="LEMON", mode="encrypt")["output"] == "LXFOPVEFRNHR"

    def test_round_trip(self):
        encrypted = run("vigenere_cipher", input="Hello, World!", key="key", mode="encrypt")["output"]
        decrypted = run("vigenere_cipher", input=encrypted, key="key", mode="decrypt")["output"]
        assert decrypted == "Hello, World!"

    def test_case_preserved(self):
        result = run("vigenere_cipher", input="HELLO", key="abc", mode="encrypt")["output"]
        assert result.isupper()

    def test_non_letters_pass_through(self):
        result = run("vigenere_cipher", input="a-1!", key="b", mode="encrypt")["output"]
        assert result == "b-1!"

    def test_key_without_letters_raises(self):
        with pytest.raises(ValueError):
            run("vigenere_cipher", input="abc", key="123", mode="encrypt")

    def test_unsupported_mode_raises(self):
        with pytest.raises(ValueError):
            run("vigenere_cipher", input="abc", key="key", mode="rot13")


# ---------------------------------------------------------------------------
# crypto
# ---------------------------------------------------------------------------

class TestAesCipher:
    def test_gcm_round_trip(self):
        encrypted = run("aes_cipher", input="hello world", mode="encrypt", cipher_mode="GCM", passphrase="secret")["output"]
        result = run("aes_cipher", input=encrypted, mode="decrypt", cipher_mode="GCM", passphrase="secret")["output"]
        assert result == "hello world"

    def test_cbc_round_trip(self):
        encrypted = run("aes_cipher", input="hello world", mode="encrypt", cipher_mode="CBC", passphrase="secret")["output"]
        result = run("aes_cipher", input=encrypted, mode="decrypt", cipher_mode="CBC", passphrase="secret")["output"]
        assert result == "hello world"

    def test_wrong_passphrase_raises(self):
        encrypted = run("aes_cipher", input="hello", mode="encrypt", cipher_mode="GCM", passphrase="right")["output"]
        with pytest.raises(ValueError):
            run("aes_cipher", input=encrypted, mode="decrypt", cipher_mode="GCM", passphrase="wrong")

    def test_empty_passphrase_raises(self):
        with pytest.raises(ValueError):
            run("aes_cipher", input="hello", mode="encrypt", passphrase="")

    def test_successive_encrypts_differ(self):
        # random IV/nonce each time, so ciphertext should not be deterministic
        a = run("aes_cipher", input="hello", mode="encrypt", cipher_mode="GCM", passphrase="k")["output"]
        b = run("aes_cipher", input="hello", mode="encrypt", cipher_mode="GCM", passphrase="k")["output"]
        assert a != b


class TestRsaKeypair:
    def test_generates_pem_private_and_public_key(self):
        output = run("rsa_keypair", key_size="2048")["output"]
        assert "-----BEGIN PRIVATE KEY-----" in output
        assert "-----END PRIVATE KEY-----" in output
        assert "-----BEGIN PUBLIC KEY-----" in output

    def test_unsupported_key_size_raises(self):
        with pytest.raises(ValueError):
            run("rsa_keypair", key_size="1024")


class TestRsaCipher:
    def _keypair(self):
        output = run("rsa_keypair", key_size="2048")["output"]
        priv, _, pub = output.partition("-----END PRIVATE KEY-----")
        return priv + "-----END PRIVATE KEY-----", pub.strip()

    def test_round_trip(self):
        priv, pub = self._keypair()
        encrypted = run("rsa_cipher", input="top secret", mode="encrypt", pem_key=pub)["output"]
        result = run("rsa_cipher", input=encrypted, mode="decrypt", pem_key=priv)["output"]
        assert result == "top secret"

    def test_invalid_pem_key_raises(self):
        with pytest.raises(ValueError):
            run("rsa_cipher", input="hi", mode="encrypt", pem_key="not a pem key")

    def test_empty_pem_key_raises(self):
        with pytest.raises(ValueError):
            run("rsa_cipher", input="hi", mode="encrypt", pem_key="")


# ---------------------------------------------------------------------------
# compression
# ---------------------------------------------------------------------------

class TestGzip:
    def test_round_trip(self):
        compressed = run("gzip", input="a" * 200, mode="compress")["output"]
        assert run("gzip", input=compressed, mode="decompress")["output"] == "a" * 200

    def test_default_mode_is_compress(self):
        assert run("gzip", input="a") == run("gzip", input="a", mode="compress")

    def test_decompress_invalid_raises(self):
        with pytest.raises(ValueError):
            run("gzip", input="not base64 gzip data", mode="decompress")

    def test_decloak_try_matches_valid_gzip(self):
        compressed = run("gzip", input="hello gzip world", mode="compress")["output"]
        assert decloak_try("gzip", compressed) == "hello gzip world"

    def test_decloak_try_none_on_plain_base64_without_gzip_magic(self):
        plain_b64 = run("base64", input="just base64, not gzip", mode="encode")["output"]
        assert decloak_try("gzip", plain_b64) is None


class TestZlib:
    def test_round_trip(self):
        compressed = run("zlib", input="b" * 200, mode="compress")["output"]
        assert run("zlib", input=compressed, mode="decompress")["output"] == "b" * 200

    def test_decloak_try_matches_valid_zlib(self):
        compressed = run("zlib", input="hello zlib world", mode="compress")["output"]
        assert decloak_try("zlib", compressed) == "hello zlib world"

    def test_decloak_try_none_on_plain_base64_without_zlib_header(self):
        plain_b64 = run("base64", input="just base64, not zlib", mode="encode")["output"]
        assert decloak_try("zlib", plain_b64) is None

    def test_decompress_invalid_raises(self):
        with pytest.raises(ValueError):
            run("zlib", input="not base64 zlib data", mode="decompress")


# ---------------------------------------------------------------------------
# analysis
# ---------------------------------------------------------------------------

class TestEntropyCalc:
    def test_empty_input_is_zero(self):
        assert run("entropy_calc", input="")["output"] == "0.0"

    def test_uniform_single_char_is_zero_not_negative_zero(self):
        # Regression: previously rendered "-0.0000 bits/byte" for a
        # single-character alphabet due to floating point rounding.
        output = run("entropy_calc", input="aaaaaaaa")["output"]
        assert not output.startswith("-")
        assert output.startswith("0.0000")

    def test_high_entropy_data_scores_higher_than_low_entropy(self):
        import os

        low = run("entropy_calc", input="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")["output"]
        high = run("entropy_calc", input=os.urandom(64).hex())["output"]
        low_val = float(low.split()[0])
        high_val = float(high.split()[0])
        assert high_val > low_val


class TestJwtDecode:
    def test_decodes_header_and_payload(self):
        # {"alg":"HS256","typ":"JWT"} . {"sub":"1234567890","name":"John Doe"} . <sig>
        token = (
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
            "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0."
            "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        )
        result = run("jwt_decode", input=token)
        assert '"alg": "HS256"' in result["output"]
        assert '"name": "John Doe"' in result["output"]
        assert "not verified" in result["note"].lower()

    def test_malformed_token_raises(self):
        with pytest.raises(ValueError):
            run("jwt_decode", input="not.a.jwt.at.all")

    def test_bad_segment_raises(self):
        with pytest.raises(ValueError):
            run("jwt_decode", input="not-base64.not-base64.sig")


class TestJwtEncode:
    def test_round_trips_with_decode(self):
        token = run(
            "jwt_encode",
            input='{"sub": "1234567890", "name": "John Doe"}',
            secret="secret",
            algorithm="HS256",
        )["output"]
        decoded = run("jwt_decode", input=token)["output"]
        assert '"name": "John Doe"' in decoded

    def test_alg_none_produces_empty_signature_segment(self):
        result = run("jwt_encode", input='{"sub": "1"}', algorithm="none")
        header, payload, signature = result["output"].split(".")
        assert signature == ""
        assert "alg=none" in result["note"]

    def test_bad_payload_json_raises(self):
        with pytest.raises(ValueError):
            run("jwt_encode", input="not json", secret="secret")

    def test_unsupported_algorithm_raises(self):
        with pytest.raises(ValueError):
            run("jwt_encode", input="{}", secret="secret", algorithm="RS256")


class TestJwtVerify:
    def test_valid_secret_verifies(self):
        token = run("jwt_encode", input='{"sub": "1"}', secret="secret", algorithm="HS256")["output"]
        result = run("jwt_verify", input=token, secret="secret", algorithm="HS256")
        assert '"valid": true' in result["output"]

    def test_wrong_secret_does_not_verify_but_still_succeeds(self):
        token = run("jwt_encode", input='{"sub": "1"}', secret="secret", algorithm="HS256")["output"]
        result = run("jwt_verify", input=token, secret="wrong-secret", algorithm="HS256")
        assert '"valid": false' in result["output"]

    def test_malformed_token_raises(self):
        with pytest.raises(ValueError):
            run("jwt_verify", input="not.a.jwt.at.all", secret="secret")


def _self_signed_pem(common_name: str = "example.com") -> str:
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(common_name)]), critical=False)
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode("ascii")


class TestX509Parse:
    def test_parses_subject_issuer_and_validity(self):
        output = run("x509_parse", input=_self_signed_pem("example.com"))["output"]
        assert "example.com" in output
        assert "not_valid_before" in output
        assert "not_valid_after" in output

    def test_includes_subject_alternative_names(self):
        output = run("x509_parse", input=_self_signed_pem("sub.example.com"))["output"]
        assert "sub.example.com" in output

    def test_malformed_pem_raises(self):
        with pytest.raises(ValueError):
            run("x509_parse", input="not a certificate")


class TestRegexExtract:
    def test_finds_all_matches(self):
        assert run("regex_extract", input="a1 b2 c3", pattern=r"\d+")["output"] == "1\n2\n3"

    def test_ignorecase_flag(self):
        assert run("regex_extract", input="Hello hello", pattern="hello", flags="i")["output"] == "Hello\nhello"

    def test_no_matches_returns_empty(self):
        assert run("regex_extract", input="abc", pattern=r"\d+")["output"] == ""

    def test_empty_pattern_raises(self):
        with pytest.raises(ValueError):
            run("regex_extract", input="abc", pattern="")

    def test_invalid_pattern_raises(self):
        with pytest.raises(ValueError):
            run("regex_extract", input="abc", pattern="(")


class TestTimestampConvert:
    def test_epoch_to_iso(self):
        assert run("timestamp_convert", input="0", mode="epoch_to_iso")["output"] == "1970-01-01T00:00:00Z"

    def test_iso_to_epoch(self):
        assert run("timestamp_convert", input="1970-01-01T00:00:00Z", mode="iso_to_epoch")["output"] == "0.0"

    def test_round_trip(self):
        iso = run("timestamp_convert", input="1700000000", mode="epoch_to_iso")["output"]
        epoch = run("timestamp_convert", input=iso, mode="iso_to_epoch")["output"]
        assert float(epoch) == 1700000000.0

    def test_non_numeric_epoch_raises(self):
        with pytest.raises(ValueError):
            run("timestamp_convert", input="not-a-number", mode="epoch_to_iso")

    def test_invalid_iso_raises(self):
        with pytest.raises(ValueError):
            run("timestamp_convert", input="not-a-date", mode="iso_to_epoch")


class TestHashIdentify:
    def test_identifies_md5_length_hash(self):
        output = run("hash_identify", input="5d41402abc4b2a76b9719d911017c592")["output"]
        assert "MD5" in output

    def test_identifies_sha256_length_hash(self):
        output = run("hash_identify", input="a" * 64)["output"]
        assert "SHA-256" in output

    def test_identifies_bcrypt_prefix(self):
        output = run("hash_identify", input="$2b$12$" + "a" * 53)["output"]
        assert output == "bcrypt"

    def test_no_match_reports_unknown(self):
        assert run("hash_identify", input="not a hash at all")["output"] == "No known hash format matched."

    def test_empty_input_raises(self):
        with pytest.raises(ValueError):
            run("hash_identify", input="")

    def test_decloak_try_matches_md5_length_hash(self):
        assert "MD5" in decloak_try("hash_identify", "5d41402abc4b2a76b9719d911017c592")

    def test_decloak_try_none_on_non_hash_shaped_input(self):
        assert decloak_try("hash_identify", "not a hash at all") is None


class TestUrlParse:
    def test_parses_components(self):
        output = run("url_parse", input="https://user:pass@example.com:8443/a/b?x=1&y=2#frag")["output"]
        assert "Scheme: https" in output
        assert "Host: example.com" in output
        assert "Port: 8443" in output
        assert "Username: user" in output
        assert "Password: pass" in output
        assert "Path: /a/b" in output
        assert "x = 1" in output
        assert "y = 2" in output
        assert "Fragment: frag" in output

    def test_path_defaults_to_root(self):
        assert "Path: /" in run("url_parse", input="https://example.com")["output"]

    def test_missing_scheme_raises(self):
        with pytest.raises(ValueError):
            run("url_parse", input="example.com/path")

    def test_empty_input_raises(self):
        with pytest.raises(ValueError):
            run("url_parse", input="")


class TestBasicAuth:
    def test_encode(self):
        assert run("basic_auth", input="user:pass", mode="encode")["output"] == "Basic dXNlcjpwYXNz"

    def test_decode(self):
        assert run("basic_auth", input="Basic dXNlcjpwYXNz", mode="decode")["output"] == "user:pass"

    def test_decode_without_prefix(self):
        assert run("basic_auth", input="dXNlcjpwYXNz", mode="decode")["output"] == "user:pass"

    def test_default_mode_is_decode(self):
        assert run("basic_auth", input="dXNlcjpwYXNz") == run("basic_auth", input="dXNlcjpwYXNz", mode="decode")

    def test_encode_without_colon_raises(self):
        with pytest.raises(ValueError):
            run("basic_auth", input="userpass", mode="encode")

    def test_decode_invalid_base64_raises(self):
        with pytest.raises(ValueError):
            run("basic_auth", input="not valid base64!!!", mode="decode")

    def test_decloak_try_matches_basic_prefix(self):
        assert decloak_try("basic_auth", "Basic dXNlcjpwYXNz") == "user:pass"

    def test_decloak_try_none_without_basic_prefix(self):
        assert decloak_try("basic_auth", "dXNlcjpwYXNz") is None

    def test_decode_without_colon_raises(self):
        import base64

        token = base64.b64encode(b"nocolonhere").decode("ascii")
        with pytest.raises(ValueError):
            run("basic_auth", input=token, mode="decode")


class TestQueryStringBuild:
    def test_builds_query_string(self):
        assert run("query_string_build", input="a=1\nb=hello world")["output"] == "a=1&b=hello+world"

    def test_strips_blank_lines(self):
        assert run("query_string_build", input="a=1\n\nb=2")["output"] == "a=1&b=2"

    def test_missing_equals_raises(self):
        with pytest.raises(ValueError):
            run("query_string_build", input="not-a-pair")

    def test_empty_input_raises(self):
        with pytest.raises(ValueError):
            run("query_string_build", input="")


# ---------------------------------------------------------------------------
# text
# ---------------------------------------------------------------------------

class TestJsonFormat:
    def test_pretty_prints(self):
        output = run("json_format", input='{"b":1,"a":2}', indent=2)["output"]
        assert output == '{\n  "b": 1,\n  "a": 2\n}'

    def test_invalid_json_raises(self):
        with pytest.raises(ValueError):
            run("json_format", input="{not valid")

    def test_invalid_indent_raises(self):
        with pytest.raises(ValueError):
            run("json_format", input="{}", indent="not-a-number")


class TestJsonMinify:
    def test_strips_whitespace(self):
        output = run("json_minify", input='{"b": 1,   "a": [1, 2, 3]}')["output"]
        assert output == '{"b":1,"a":[1,2,3]}'

    def test_invalid_json_raises(self):
        with pytest.raises(ValueError):
            run("json_minify", input="{not valid")


class TestNumberBaseConvert:
    @pytest.mark.parametrize(
        "value,from_base,to_base,expected",
        [
            ("255", "decimal", "hexadecimal", "0xff"),
            ("255", "decimal", "binary", "0b11111111"),
            ("255", "decimal", "octal", "0o377"),
            ("0xff", "hexadecimal", "decimal", "255"),
            ("0b1010", "binary", "decimal", "10"),
        ],
    )
    def test_conversions(self, value, from_base, to_base, expected):
        assert run("number_base_convert", input=value, from_base=from_base, to_base=to_base)["output"] == expected

    def test_invalid_number_raises(self):
        with pytest.raises(ValueError):
            run("number_base_convert", input="zz", from_base="decimal", to_base="hexadecimal")

    def test_unsupported_base_raises(self):
        with pytest.raises(ValueError):
            run("number_base_convert", input="1", from_base="roman", to_base="decimal")


class TestUuidGenerate:
    def test_v4_is_valid_uuid(self):
        import uuid

        output = run("uuid_generate", version="4")["output"]
        assert uuid.UUID(output).version == 4

    def test_unsupported_version_raises(self):
        with pytest.raises(ValueError):
            run("uuid_generate", version="7")

    def test_successive_calls_differ(self):
        a = run("uuid_generate", version="4")["output"]
        b = run("uuid_generate", version="4")["output"]
        assert a != b


class TestRandomStringGenerate:
    def test_length_is_respected(self):
        output = run("random_string_generate", length=32, charset="alphanumeric")["output"]
        assert len(output) == 32

    def test_charset_is_respected(self):
        output = run("random_string_generate", length=64, charset="digits")["output"]
        assert all(c.isdigit() for c in output)

    def test_length_out_of_range_raises(self):
        with pytest.raises(ValueError):
            run("random_string_generate", length=0)
        with pytest.raises(ValueError):
            run("random_string_generate", length=99999)

    def test_unsupported_charset_raises(self):
        with pytest.raises(ValueError):
            run("random_string_generate", length=8, charset="not-a-real-charset")


class TestCaseConvert:
    def test_upper(self):
        assert run("case_convert", input="hello", mode="upper")["output"] == "HELLO"

    def test_snake_case(self):
        assert run("case_convert", input="Hello World", mode="snake_case")["output"] == "hello_world"

    def test_camel_case(self):
        assert run("case_convert", input="hello world", mode="camelCase")["output"] == "helloWorld"

    def test_unsupported_mode_raises(self):
        with pytest.raises(ValueError):
            run("case_convert", input="hello", mode="kebab_case")


class TestColorConvert:
    def test_hex_to_rgb(self):
        result = run("color_convert", input="#ff0000", from_format="hex", to_format="rgb")["output"]
        assert result == "rgb(255, 0, 0)"

    def test_shorthand_hex_to_rgb(self):
        result = run("color_convert", input="#f00", from_format="hex", to_format="rgb")["output"]
        assert result == "rgb(255, 0, 0)"

    def test_rgb_to_hsl(self):
        result = run("color_convert", input="rgb(255, 0, 0)", from_format="rgb", to_format="hsl")["output"]
        assert result == "hsl(0, 100%, 50%)"

    def test_hsl_to_hex(self):
        result = run("color_convert", input="hsl(0, 100%, 50%)", from_format="hsl", to_format="hex")["output"]
        assert result == "#ff0000"

    def test_invalid_hex_raises(self):
        with pytest.raises(ValueError):
            run("color_convert", input="not-a-color", from_format="hex", to_format="rgb")

    def test_out_of_range_rgb_raises(self):
        with pytest.raises(ValueError):
            run("color_convert", input="rgb(999, 0, 0)", from_format="rgb", to_format="hex")


class TestLineTools:
    def test_sort(self):
        assert run("line_tools", input="b\na\nc", mode="sort")["output"] == "a\nb\nc"

    def test_unique_preserves_first_occurrence_order(self):
        assert run("line_tools", input="b\na\nb\nc", mode="unique")["output"] == "b\na\nc"

    def test_reverse(self):
        assert run("line_tools", input="a\nb\nc", mode="reverse")["output"] == "c\nb\na"

    def test_unsupported_mode_raises(self):
        with pytest.raises(ValueError):
            run("line_tools", input="a\nb", mode="shuffle")


# ---------------------------------------------------------------------------
# networking
# ---------------------------------------------------------------------------

class TestCidrCalculator:
    def test_computes_network_details(self):
        output = run("cidr_calculator", input="10.0.0.0/24")["output"]
        assert "Network: 10.0.0.0" in output
        assert "Broadcast: 10.0.0.255" in output
        assert "Usable hosts: 254" in output

    def test_non_strict_host_bits_set(self):
        # strict=False means a host address with bits set is normalized to its network
        output = run("cidr_calculator", input="10.0.0.5/24")["output"]
        assert "Network: 10.0.0.0" in output

    def test_empty_input_raises(self):
        with pytest.raises(ValueError):
            run("cidr_calculator", input="")

    def test_invalid_cidr_raises(self):
        with pytest.raises(ValueError):
            run("cidr_calculator", input="not-a-cidr")


class TestUnixPermissions:
    def test_octal_to_symbolic(self):
        assert run("unix_permissions", input="755")["output"] == "rwxr-xr-x"

    def test_symbolic_to_octal(self):
        assert run("unix_permissions", input="rwxr-xr-x")["output"] == "755"

    def test_symbolic_with_leading_file_type_char(self):
        assert run("unix_permissions", input="-rwxr-xr-x")["output"] == "755"

    def test_setuid_round_trip(self):
        symbolic = run("unix_permissions", input="4755")["output"]
        assert symbolic == "rwsr-xr-x"
        assert run("unix_permissions", input=symbolic)["output"] == "4755"

    def test_setuid_without_exec_uses_capital_s(self):
        symbolic = run("unix_permissions", input="4655")["output"]
        assert symbolic == "rwSr-xr-x"
        assert run("unix_permissions", input=symbolic)["output"] == "4655"

    def test_sticky_bit_round_trip(self):
        symbolic = run("unix_permissions", input="1777")["output"]
        assert symbolic == "rwxrwxrwt"
        assert run("unix_permissions", input=symbolic)["output"] == "1777"

    def test_invalid_input_raises(self):
        with pytest.raises(ValueError):
            run("unix_permissions", input="not-permissions")

    def test_empty_input_raises(self):
        with pytest.raises(ValueError):
            run("unix_permissions", input="")


# ---------------------------------------------------------------------------
# compare
# ---------------------------------------------------------------------------

class TestTextDiff:
    def test_identical_texts_produce_no_diff_lines(self):
        output = run("text_diff", input="a\nb\nc", compare="a\nb\nc", mode="unified")["output"]
        assert output == ""

    def test_added_line_shown_in_unified_diff(self):
        output = run("text_diff", input="a\nb", compare="a\nb\nc", mode="unified")["output"]
        assert "+c" in output

    def test_removed_line_shown_in_unified_diff(self):
        output = run("text_diff", input="a\nb\nc", compare="a\nb", mode="unified")["output"]
        assert "-c" in output

    def test_line_by_line_mode_distinguishes_differing_pair(self):
        output = run("text_diff", input="a\nb", compare="a\nc", mode="line-by-line")["output"]
        assert "- b" in output
        assert "+ c" in output

    def test_unsupported_mode_raises(self):
        with pytest.raises(ValueError):
            run("text_diff", input="a", compare="b", mode="side-by-side")
