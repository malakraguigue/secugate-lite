import unittest

from src.contrat import Signal
from src.detection import est_deja_vu


def sig():
    return Signal(
        "SIG-00001",
        "2026-10-05T10:00:00Z",
        "ACCES",
        "10.0.0.5",
        "web-app",
        "ACCES",
        "FAIBLE",
        "GET /home -> 200"
    )


class TestDetection(unittest.TestCase):

    def test_doublon(self):
        vus = set()

        self.assertFalse(est_deja_vu(sig(), vus))
        self.assertTrue(est_deja_vu(sig(), vus))


if __name__ == "__main__":
    unittest.main()
    