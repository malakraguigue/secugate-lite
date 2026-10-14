
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
    if sig.type == "LOGIN_ECHEC":
        if nb_echecs >= 5:
            return "CRITIQUE"
        return "MOYENNE"

    return sig.gravite


def analyser(sig: Signal, base: dict, nb_echecs: int = 0) -> Verdict:
    niveau = evaluer(sig, nb_echecs)

    procedures = chercher_procedures(sig, base)

    if procedures:
        explication = " | ".join(procedures)
    else:
        explication = "Cause inconnue : analyse manuelle requise"

    if sig.type == "LOGIN_ECHEC" and niveau == "CRITIQUE":
        action = f"Bloquer l'IP {sig.ip}"
    elif sig.type == "FAILLE":
        action = f"Corriger la faille dans {sig.cible}"
    else:
        action = "Surveiller"

    sensible = niveau in ["ELEVEE", "CRITIQUE"]

    verdict = Verdict(
        signal_id=sig.id,
        niveau=niveau,
        explication=explication,
        action=action,
        sensible=sensible,
        sources=[sig.source]
    )

    sig.statut = "ANALYSE"

    return verdict
