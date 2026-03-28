# GenieACS Docker Frontend

Docker-basierte Flask-Webanwendung als einfaches Frontend für eine GenieACS-Umgebung.

## Features

- Login-geschützte Oberfläche (Bootstrap 5)
- Initiales Online-Setup: Wenn kein Benutzer existiert, wird automatisch die Admin-Erstellung angezeigt
- Benutzerverwaltung mit Rollen (`admin`, `editor`, `viewer`)
- Web-Konfiguration der ACS-API-URL
- Persistente SQLite-Datenbank im Docker-Volume (`./data`)

## Starten

```bash
docker compose up --build
```

Danach ist die Oberfläche verfügbar unter: `http://localhost:8080`


Der Compose-Stack startet zusätzlich einen dedizierten `udpst-server` (OB-UDPST, TR-471-kompatibel) auf `25000/udp`.
Damit laufen IPLayerCapacity-Tests nicht mehr gegen den einfachen Echo-Server, sondern gegen einen echten TR-471-Server.

## Ersteinrichtung

Beim ersten Start (leere Datenbank) wird die Seite `/setup` angezeigt:

1. Admin-Benutzername setzen
2. Passwort setzen
3. ACS-API-URL hinterlegen

Nach dem Speichern kann man sich normal einloggen.

## Benutzerrollen

- **admin**: Darf Benutzer verwalten und ACS-API-URL ändern
- **editor**: Kann sich anmelden und Dashboard sehen
- **viewer**: Kann sich anmelden und Dashboard sehen

## Konfiguration

Umgebungsvariablen in `docker-compose.yml`:

- `SECRET_KEY`: Session-Sicherheit (in Produktion ändern)
- `DATABASE_URL`: SQLAlchemy-Connection-String
- `UDPST_SERVER_HOST`: Bind-Adresse des integrierten lokalen UDPST-Health-Servers in der Frontend-App
- `UDPST_SERVER_PORT`: UDP-Port des integrierten lokalen UDPST-Health-Servers
- `UDPST_TEST_HOST`: **Öffentlich erreichbare IP oder DNS-Name des Docker-Hosts**, auf dem `udpst-server` auf Port `25000/udp` veröffentlicht ist
- `UDPST_TEST_PORT`: Zielport für den UDPST-Test (standardmäßig `25000`)
- `UDPST_TEST_ROLE`: Rolle für den IPLayerCapacity-Test (`Receiver` oder `Sender`)

## Hinweis

Dieses Projekt stellt ein administratives Frontend bereit und kann als Grundlage für weitere GenieACS-API-Integrationen genutzt werden.


## TR-471 / udpst-Container

Der Service `udpst-server` wird aus `docker/obudpst/Dockerfile` gebaut und nutzt das offizielle `BroadbandForum/obudpst`-Projekt als Server-Implementierung.
