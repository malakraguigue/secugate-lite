import unittest

from src.collecte import masquer_ip, masquer_parametres, normaliser_acces, normaliser_scan

LIGNE = "2026-10-05 10:01:10 192.168.1.15 POST /login 401"

RAPPORT = {
    "rule": "S3649",
    "component": "backend",
    "severity": "blocker",
    "message": "injection SQL possible",
    "date": "2026-10-05T10:05:00Z",
}


class TestCollecte(unittest.TestCase):

    # masquer_ip
    def test_masquer_ip(self):
        self.assertEqual(masquer_ip("192.168.1.15"), "192.168.1.x")

    def test_masquer_ip_invalide(self):
        with self.assertRaises(ValueError):
            masquer_ip("192.168.1")

    # masquer_parametres
    def test_masquer_token(self):
        self.assertEqual(masquer_parametres("/api?id=3&token=abc123"),
                         "/api?id=3&token=[MASQUE]")

    def test_masquer_sans_tenir_compte_casse(self):
        self.assertEqual(masquer_parametres("/login?PASSWORD=secret&x=1"),
                         "/login?PASSWORD=[MASQUE]&x=1")

    def test_chemin_sans_parametre_sensible(self):
        self.assertEqual(masquer_parametres("/api?id=3"), "/api?id=3")

    # normaliser_acces
    def test_normaliser_acces(self):
        sig = normaliser_acces(LIGNE, 42)
        self.assertEqual(sig.id, "SIG-00042")
        self.assertEqual(sig.timestamp, "2026-10-05T10:01:10Z")
        self.assertEqual(sig.source, "ACCES")
        self.assertEqual(sig.ip, "192.168.1.15")
        self.assertEqual(sig.cible, "web-app")
        self.assertEqual(sig.type, "LOGIN_ECHEC")
        self.assertEqual(sig.gravite, "MOYENNE")
        self.assertEqual(sig.message, "POST /login -> 401 depuis 192.168.1.x")

    def test_login_403_avec_parametres(self):
        sig = normaliser_acces("2026-10-05 10:01:10 10.0.0.5 POST /login?next=/home 403", 1)
        self.assertEqual(sig.type, "LOGIN_ECHEC")

    def test_401_hors_login_est_un_acces(self):
        sig = normaliser_acces("2026-10-05 10:01:10 10.0.0.5 GET /admin 401", 1)
        self.assertEqual(sig.type, "ACCES")

    def test_gravite_selon_statut(self):
        base = "2026-10-05 10:00:00 10.0.0.5 GET /home "
        self.assertEqual(normaliser_acces(base + "500", 1).gravite, "ELEVEE")
        self.assertEqual(normaliser_acces(base + "404", 1).gravite, "MOYENNE")
        self.assertEqual(normaliser_acces(base + "200", 1).gravite, "FAIBLE")

    def test_message_masque_les_parametres(self):
        sig = normaliser_acces("2026-10-05 10:03:00 10.0.0.7 GET /api/users?id=3&token=abc123 200", 8)
        self.assertEqual(sig.message, "GET /api/users?id=3&token=[MASQUE] -> 200 depuis 10.0.0.x")

    def test_cible_personnalisee(self):
        self.assertEqual(normaliser_acces(LIGNE, 1, cible="api").cible, "api")

    def test_ligne_trop_courte(self):
        with self.assertRaises(ValueError):
            normaliser_acces("2026-10-05 10:01:10 192.168.1.15 POST", 1)

    # normaliser_scan
    def test_normaliser_scan(self):
        sig = normaliser_scan(RAPPORT, 9)
        self.assertEqual(sig.id, "SIG-00009")
        self.assertEqual(sig.source, "SCAN")
        self.assertEqual(sig.ip, "")
        self.assertEqual(sig.cible, "backend")
        self.assertEqual(sig.type, "FAILLE")
        self.assertEqual(sig.timestamp, "2026-10-05T10:05:00Z")
        self.assertEqual(sig.gravite, "CRITIQUE")
        self.assertEqual(sig.message, "Faille S3649 : injection SQL possible")

    def test_gravite_scan_sans_tenir_compte_casse(self):
        self.assertEqual(normaliser_scan(dict(RAPPORT, severity="MAJOR"), 1).gravite, "MOYENNE")

    def test_gravite_scan_inconnue(self):
        self.assertEqual(normaliser_scan(dict(RAPPORT, severity="info"), 1).gravite, "FAIBLE")

    def test_cle_manquante(self):
        rapport = dict(RAPPORT)
        del rapport["rule"]
        with self.assertRaises(ValueError):
            normaliser_scan(rapport, 1)


if __name__ == "__main__":
    unittest.main()