import contextlib
import io
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import playground


class PlaygroundTests(unittest.TestCase):
    def test_sha256_known_vector(self):
        self.assertEqual(
            playground.digest(b"abc", "sha256"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        )

    def test_sha512_known_vector(self):
        self.assertTrue(playground.digest(b"abc", "sha512").startswith("ddaf35a193617aba"))

    def test_md5_known_vector(self):
        self.assertEqual(playground.digest(b"abc", "md5"),
                         "900150983cd24fb0d6963f7d28e17f72")

    def test_unknown_algorithm(self):
        with self.assertRaises(ValueError):
            playground.digest(b"abc", "sha1")

    def test_hmac_known_vector(self):
        # RFC 4231, test case 2
        self.assertEqual(
            playground.hmac_hex(b"Jefe", b"what do ya want for nothing?", "sha256"),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
        )

    def test_pbkdf2_known_vector(self):
        # RFC 6070 style vector with low iterations for speed
        self.assertEqual(
            playground.pbkdf2("password", b"salt", 1, "sha256"),
            "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b",
        )

    def test_verify_roundtrip(self):
        salt = b"0123456789abcdef"
        digest_hex = playground.pbkdf2("s3cret", salt, 1000)
        self.assertTrue(playground.verify_pbkdf2("s3cret", salt, 1000, digest_hex))
        self.assertFalse(playground.verify_pbkdf2("wrong", salt, 1000, digest_hex))

    def test_constant_time_compare(self):
        self.assertTrue(playground.constant_time_equal("abc", "abc"))
        self.assertFalse(playground.constant_time_equal("abc", "abd"))

    def test_cli_digest(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = playground.main(["sha256", "--text", "abc"])
        self.assertEqual(code, 0)
        self.assertIn("ba7816bf", buf.getvalue())

    def test_cli_invalid_iterations(self):
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(
                playground.main(["pbkdf2", "--password", "x", "--iterations", "0"]), 2)


if __name__ == "__main__":
    unittest.main()
