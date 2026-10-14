
from src.contrat import Signal, Verdict


def est_deja_vu(sig: Signal, vus: set) -> bool:
    cle = (
        sig.timestamp,
        sig.source,
        sig.ip,
        sig.cible,
        sig.type,
        sig.message
    )

    if cle in vus:
        return True

    vus.add(cle)
    return False


def compter_echecs(sig: Signal, compteur: dict) -> int:
    if sig.type == "LOGIN_ECHEC":
        ip = sig.ip
        compteur[ip] = compteur.get(ip, 0) + 1
        return compteur[ip]

    return 0


def chercher_procedures(sig: Signal, base: dict) -> list:
    procedures = []

    for mot_cle, procedure in base.items():
        if mot_cle.lower() in sig.message.lower():
            procedures.append(procedure)

    return procedures


def evaluer(sig: Signal, nb_echecs: int = 0) -> str:
    raise NotImplementedError


def analyser(sig: Signal, base: dict, nb_echecs: int = 0) -> Verdict:
    raise NotImplementedError
