import re

from src.contrat import Signal
PARAMS_SENSIBLES = re.compile(r"\b(token|password|session|key)=[^&\s]*", re.IGNORECASE)

def masquer_ip(ip: str) -> str:
    parties = ip.split(".")
    if len(parties) != 4:
        raise ValueError(f"Adresse IP invalide : {ip}")
    parties[-1] = "x"
    return ".".join(parties)
def masquer_parametres(chemin: str) -> str:
    return PARAMS_SENSIBLES.sub(r"\1=[MASQUE]", chemin)
def normaliser_acces(ligne: str, numero: int, cible: str = "web-app") -> Signal:
 raise NotImplementedError
def normaliser_scan(rapport: dict, numero: int) -> Signal:
 raise NotImplementedError