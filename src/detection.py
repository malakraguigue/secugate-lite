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
 raise NotImplementedError
def chercher_procedures(sig: Signal, base: dict) -> list:
 raise NotImplementedError
def evaluer(sig: Signal, nb_echecs: int = 0) -> str:
 raise NotImplementedError
def analyser(sig: Signal, base: dict, nb_echecs: int = 0) -> Verdict:
 raise NotImplementedError