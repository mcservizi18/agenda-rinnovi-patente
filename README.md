# Agenda Rinnovi Patente — Agenzia MC Servizi

Agenda delle visite di rinnovo patente con accesso tramite nome utente e password.

## Cosa fa
- **Agenda**: giornate del medico divise in orari prenotabili, schede appuntamento con documenti consegnati, importo, stato.
- **Appuntamenti**: ricerca per nome, telefono o numero di patente; filtri per documenti mancanti, pratiche da chiudere, importi da incassare.
- **Da richiamare**: clienti con la patente in scadenza, con messaggio WhatsApp pronto.
- **Utenti** (solo amministratore): crea i collaboratori, assegna il ruolo, disattiva chi non deve più entrare.

## Ruoli
| Ruolo | Può fare |
|---|---|
| Amministratore | tutto, compresa la gestione degli utenti |
| Operatore | prenota, modifica ed elimina appuntamenti, giornate e clienti da richiamare |
| Sola consultazione | vede l'agenda senza modificarla |

Ogni nuovo utente riceve una password provvisoria e al primo accesso deve sceglierne una sua.

## Avvio in locale
Serve solo Node.js 18 o successivo, nessun pacchetto da installare.

```
ADMIN_PASSWORD=unapasswordprovvisoria node server.js
```
Poi apri http://localhost:3000 ed entra con utente `admin`.

## Variabili d'ambiente
| Variabile | A cosa serve |
|---|---|
| `DATA_DIR` | cartella dei dati (su Railway: `/data`, il volume) |
| `ADMIN_USERNAME` | nome dell'amministratore creato al primo avvio (predefinito `admin`) |
| `ADMIN_PASSWORD` | password provvisoria dell'amministratore al primo avvio; se manca ne viene generata una e scritta nei log |
| `PORT` | porta (Railway la imposta da solo) |

## Dati e sicurezza
- Tutto è salvato in `DATA_DIR/db.json`; ogni giorno viene fatta una copia in `DATA_DIR/backup` (ultime 14).
- Le password sono salvate cifrate (scrypt), mai in chiaro.
- Dopo 10 tentativi sbagliati dallo stesso indirizzo l'accesso si blocca per 15 minuti.
- La sessione dura 30 giorni; "Esci" la chiude subito. Cambiando password si chiudono le sessioni sugli altri dispositivi.
