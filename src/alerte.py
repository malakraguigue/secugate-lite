from src.contrat import Alerte, Signal, Verdict

CANAUX = {
    "CRITIQUE": "TELEPHONE",
    "ELEVEE": "SLACK",
    "MOYENNE": "EMAIL",
    "FAIBLE": "TABLEAU",
}

REPONSES_OUI = {"o", "oui", "ok", "yes"}


def choisir_canal(niveau: str) -> str:
    if niveau not in CANAUX:
        raise ValueError(f"Niveau inconnu : {niveau}")
    return CANAUX[niveau]
def rediger(sig: Signal, verdict: Verdict) -> str:
 raise NotImplementedError
def alerter(sig: Signal, verdict: Verdict, journal: list) -> Alerte:
 raise NotImplementedError
def valider_action(verdict: Verdict, reponse: str) -> bool:
 raise NotImplementedError