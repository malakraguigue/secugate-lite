
import unittest

from src.contrat import Signal
from src.detection import est_deja_vu, compter_echecs


def sig(type_="ACCES", gravite="FAIBLE",
        message="GET /home -> 200", ip="10.0.0.5"):
    return Signal(
        "SIG-00001",
        "2026-10-05T10:00:00Z",
        "ACCES",
        ip,
        "web-app",
        type_,
        gravite,
        message
    )


class TestDetection(unittest.TestCase):

    def test_doublon(self):
        vus = set()
        self.assertFalse(est_deja_vu(sig(), vus))
        self.assertTrue(est_deja_vu(sig(), vus))

    def test_compter_echecs(self):
        compteur = {}
        e = sig("LOGIN_ECHEC", "MOYENNE")

        self.assertEqual(compter_echecs(e, compteur), 1)
        self.assertEqual(compter_echecs(e, compteur), 2)
        self.assertEqual(compteur["10.0.0.5"], 2)


if __name__ == "__main__":
    unittest.main()
