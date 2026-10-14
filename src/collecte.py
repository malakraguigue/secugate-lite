import re

from src.contrat import Signal
PARAMS_SENSIBLES = re.compile(r"\b(token|password|session|key)=[^&\s]*", re.IGNORECASE)
GRAVITES_SCAN = {
    "blocker": "CRITIQUE",
    "critical": "ELEVEE",
    "major": "MOYENNE",
    "minor": "FAIBLE",
}
def masquer_ip(ip: str) -> str:
    parties = ip.split(".")
    if len(parties) != 4:
        raise ValueError(f"Adresse IP invalide : {ip}")
    parties[-1] = "x"
    return ".".join(parties)
def masquer_parametres(chemin: str) -> str:
    return PARAMS_SENSIBLES.sub(r"\1=[MASQUE]", chemin)
def normaliser_acces(ligne: str, numero: int, cible: str = "web-app") -> Signal:
    champs = ligne.split()
    if len(champs) < 6:
        raise ValueError(f"Ligne de log invalide : {ligne}")
    date, heure, ip, methode, chemin, statut = champs[:6]

    chemin_seul = chemin.split("?")[0]
    if chemin_seul == "/login" and statut in ("401", "403"):
        type_signal = "LOGIN_ECHEC"
    else:
        type_signal = "ACCES"

    if statut.startswith("5"):
        gravite = "ELEVEE"
    elif statut.startswith("4"):
        gravite = "MOYENNE"
    else:
        gravite = "FAIBLE"

    message = f"{methode} {masquer_parametres(chemin)} -> {statut} depuis {masquer_ip(ip)}"

    return Signal(
        id=f"SIG-{numero:05d}",
        timestamp=f"{date}T{heure}Z",
        source="ACCES",
        ip=ip,
        cible=cible,
        type=type_signal,
        gravite=gravite,
        message=message,
    )
def normaliser_scan(rapport: dict, numero: int) -> Signal:
    for cle in ("rule", "component", "severity", "message", "date"):
        if cle not in rapport:
            raise ValueError(f"Cle manquante dans le rapport : {cle}")

    gravite = GRAVITES_SCAN.get(rapport["severity"].lower(), "FAIBLE")

    return Signal(
        id=f"SIG-{numero:05d}",
        timestamp=rapport["date"],
        source="SCAN",
        ip="",
        cible=rapport["component"],
        type="FAILLE",
        gravite=gravite,
        message=f"Faille {rapport['rule']} : {rapport['message']}",
    )