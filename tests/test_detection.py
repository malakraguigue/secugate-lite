
import unittest

from src.contrat import Signal, PROCEDURES
from src.detection import (
    est_deja_vu,
    compter_echecs,
    chercher_procedures,
    evaluer,
    analyser
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
        e = sig("FAILLE", "ELEVEE", "injection SQL")
        resultat = chercher_procedures(e, PROCEDURES)
        self.assertEqual(resultat, [PROCEDURES["injection"]])

    def test_aucune_procedure(self):
        e = sig(message="Probleme inconnu")
        self.assertEqual(chercher_procedures(e, PROCEDURES), [])

    def test_recherche_sans_casse(self):
        e = sig(message="INJECTION et TOKEN detectes")
        self.assertEqual(
            chercher_procedures(e, PROCEDURES),
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

    def test_analyser_login_critique(self):
        e = sig("LOGIN_ECHEC", "MOYENNE", "POST /login")
        verdict = analyser(e, PROCEDURES, 5)

        self.assertEqual(verdict.niveau, "CRITIQUE")
        self.assertEqual(verdict.action, "Bloquer l'IP 10.0.0.5")
        self.assertTrue(verdict.sensible)
        self.assertEqual(verdict.sources, ["ACCES"])
        self.assertEqual(e.statut, "ANALYSE")

    def test_analyser_faille(self):
        e = sig("FAILLE", "ELEVEE", "injection SQL")
        verdict = analyser(e, PROCEDURES)

        self.assertEqual(
            verdict.action,
            "Corriger la faille dans web-app"
        )
        self.assertEqual(verdict.explication, PROCEDURES["injection"])
        self.assertTrue(verdict.sensible)

    def test_analyser_normal(self):
        e = sig()
        verdict = analyser(e, PROCEDURES)

        self.assertEqual(verdict.niveau, "FAIBLE")
        self.assertEqual(verdict.action, "Surveiller")
        self.assertFalse(verdict.sensible)
        self.assertEqual(
            verdict.explication,
            "Cause inconnue : analyse manuelle requise"
        )


if __name__ == "__main__":
    unittest.main()
