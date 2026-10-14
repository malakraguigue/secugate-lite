
import unittest

from src.contrat import Signal, PROCEDURES
from src.detection import (
    est_deja_vu,
    compter_echecs,
    chercher_procedures,
    evaluer
)


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

    def test_chercher_procedures(self):
        e = sig(
            "FAILLE",
            "ELEVEE",
            "Une injection SQL a ete detectee"
        )

        resultat = chercher_procedures(e, PROCEDURES)

        self.assertEqual(resultat, [PROCEDURES["injection"]])

    def test_aucune_procedure(self):
        e = sig(message="Probleme inconnu")
        resultat = chercher_procedures(e, PROCEDURES)

        self.assertEqual(resultat, [])

    def test_recherche_sans_casse(self):
        e = sig(message="INJECTION et TOKEN detectes")
        resultat = chercher_procedures(e, PROCEDURES)

        self.assertEqual(
            resultat,
            [PROCEDURES["injection"], PROCEDURES["token"]]
        )

    def test_evaluer_echecs_login(self):
        e = sig("LOGIN_ECHEC", "MOYENNE")

        self.assertEqual(evaluer(e, 5), "CRITIQUE")
        self.assertEqual(evaluer(e, 4), "MOYENNE")
        self.assertEqual(evaluer(e, 6), "CRITIQUE")

    def test_evaluer_autre_signal(self):
        e = sig("FAILLE", "ELEVEE")

        self.assertEqual(evaluer(e), "ELEVEE")


if __name__ == "__main__":
    unittest.main()
