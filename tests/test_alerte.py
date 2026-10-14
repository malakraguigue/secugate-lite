import unittest

from src.alerte import alerter, choisir_canal, rediger, valider_action
from src.contrat import Signal, Verdict


def exemple(sensible=True, niveau="CRITIQUE"):
    s = Signal("SIG-00125", "2026-10-05T10:01:31Z", "ACCES", "192.168.1.15",
               "web-app", "LOGIN_ECHEC", "MOYENNE",
               "POST /login -> 401 depuis 192.168.1.x")
    v = Verdict("SIG-00125", niveau, "Echecs de connexion",
                "Bloquer l'IP 192.168.1.15", sensible, ["ACCES"])
    return s, v


class TestAlerte(unittest.TestCase):

    # choisir_canal
    def test_canaux(self):
        self.assertEqual(choisir_canal("CRITIQUE"), "TELEPHONE")
        self.assertEqual(choisir_canal("ELEVEE"), "SLACK")
        self.assertEqual(choisir_canal("MOYENNE"), "EMAIL")
        self.assertEqual(choisir_canal("FAIBLE"), "TABLEAU")

    def test_canal_niveau_inconnu(self):
        with self.assertRaises(ValueError):
            choisir_canal("URGENT")

    # rediger
    def test_rediger(self):
        s, v = exemple()
        attendu = ("[CRITIQUE] Cible : web-app\n"
                   "Signal : POST /login -> 401 depuis 192.168.1.x\n"
                   "Explication : Echecs de connexion\n"
                   "Action proposee : Bloquer l'IP 192.168.1.15\n"
                   "Sources : ACCES")
        self.assertEqual(rediger(s, v), attendu)

    def test_rediger_plusieurs_sources(self):
        s, v = exemple()
        v.sources = ["ACCES", "SCAN"]
        self.assertTrue(rediger(s, v).endswith("Sources : ACCES, SCAN"))

    def test_rediger_cinq_lignes(self):
        s, v = exemple()
        self.assertEqual(len(rediger(s, v).split("\n")), 5)

    # alerter
    def test_alerter(self):
        s, v = exemple()
        journal = []
        al = alerter(s, v, journal)
        self.assertEqual(al.signal_id, "SIG-00125")
        self.assertEqual(al.canal, "TELEPHONE")
        self.assertEqual(al.destinataire, "equipe-secu")
        self.assertEqual(al.texte, rediger(s, v))
        self.assertEqual(journal, [al])
        self.assertEqual(s.statut, "ALERTE")

    def test_alerter_niveau_inconnu(self):
        s, v = exemple(niveau="INCONNU")
        with self.assertRaises(ValueError):
            alerter(s, v, [])

    # valider_action
    def test_validation(self):
        _, v = exemple()
        self.assertTrue(valider_action(v, " OUI "))
        self.assertFalse(valider_action(v, "n"))

    def test_validation_reponses_acceptees(self):
        _, v = exemple()
        for reponse in ["o", "oui", "ok", "yes", "Yes", "OK"]:
            self.assertTrue(valider_action(v, reponse))

    def test_validation_refus(self):
        _, v = exemple()
        for reponse in ["", "non", "peut-etre"]:
            self.assertFalse(valider_action(v, reponse))

    def test_action_non_sensible(self):
        _, v = exemple(sensible=False)
        self.assertTrue(valider_action(v, "n"))


if __name__ == "__main__":
    unittest.main()