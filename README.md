![Badge](https://hitscounter.dev/api/hit?url=https%3A%2F%2Fgithub.com%2Fgeimist%2FUpdate_Blocklist&label=Visitors&icon=github&color=%23ffc107&message=&style=flat&tz=Europe%2FBerlin)

# Update_Blocklist

aktualisiert / importiert von [blocklist.de](http://www.blocklist.de/de/index.html) gesperrte IPs in die IP-Blocklist des Synology DSM

* der erste Programmlauf kann sehr lange dauern (~~ggf. über Stunden~~) / spätere Programmläufe dauern dann meist nur wenige Sekunden
* aufgrund der sich schnell ändernten Onlineliste, läuft das Skript bei mir aller 10 Minuten
* [step-by-step Anleitung](https://www.synology-forum.de/threads/staendige-anmeldeversuche-am-dsm.122250/post-1015901)

([Quelle](https://www.synology-forum.de/showthread.html?103687-Freigabe-Blockierliste-automatisch-updaten))

--------------
updates / imports IPs blocked by [blocklist.de](http://www.blocklist.de/de/index.html) into the IP blocklist of the Synology DSM

* the first program run can take a very long time (~~possibly over hours~~) / later program runs then usually take only a few seconds
* due to the fast changing online list, the script runs every 10 minutes for me

([Source](https://www.synology-forum.de/showthread.html?103687-Freigabe-Blockierliste-automatisch-updaten))

## AutoBan (DSM 7 Paket)

Das Paket **AutoBan** kapselt dasselbe Skript mit Oberfläche, Zeitplan und einem kleinen setuid-Helfer. Das Skript [`update_blocklist.sh`](update_blocklist.sh) bleibt der lesbare Ablauf. Gebaut wird es unter `spk/`. Erstellt mit der Unterstützung von Cursor.

```sh
spk/build_spk.sh 1.0.0
```

Dafür werden Go, `rsvg-convert` oder ImageMagick und `fakeroot` benötigt. Das Ergebnis ist `AutoBan_1.0.0.spk` (DSM 7, x86_64, i686, armv7, armv8).

Nach der Installation im Paketzentrum:

- Einstellungen, Läufe, Protokoll und Sicherungen liegen in der AutoBan-Oberfläche.
- Konfiguration und Statistik: `/var/packages/AutoBan/var/app.db`
- Protokoll (maximal 1000 Zeilen): `/var/packages/AutoBan/var/log/autoban.log`
- Sicherungen der Systemdatenbank: `/var/packages/AutoBan/var/db_backups/` (`pristine`, `latest`, `hour`, `day`, `week`, `month`)
- Nur `ab-helper` schreibt `/etc/synoautoblock.db`. Beim ersten Start prüfen, dass die Datei root gehört und das Setuid-Bit gesetzt ist (`-r-sr-x---`).

Ein bisher per Aufgabenplaner gestartetes Root-Skript kann entfallen, sobald das Paket läuft. Die Standalone-Nutzung des Skripts bleibt möglich.
