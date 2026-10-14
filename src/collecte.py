import re

from src.contrat import Signal


def masquer_ip(ip: str) -> str:
    parties = ip.split(".")
    if len(parties) != 4:
        raise ValueError(f"Adresse IP invalide : {ip}")
    parties[-1] = "x"
    return ".".join(parties)
def masquer_parametres(chemin: str) -> str:
 raise NotImplementedError
def normaliser_acces(ligne: str, numero: int, cible: str = "web-app") -> Signal:
 raise NotImplementedError
def normaliser_scan(rapport: dict, numero: int) -> Signal:
 raise NotImplementedError