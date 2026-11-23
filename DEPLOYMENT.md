# Desplegament a Railway

El servei és una API FastAPI amb SQLite. `railway.json` defineix la construcció amb Nixpacks, l'arrencada amb `uvicorn`, la comprovació de salut i un volum a `/data`. Sense `SESSION_SECRET` no arrenca.

## 1. Crear el projecte

1. Entra a https://railway.app i crea un projecte nou.
2. Tria l'opció de desplegar des d'un repositori de GitHub.
3. Selecciona `julsehn/Password-Manager-Cloud` i la branca `main`.
4. Deixa el directori arrel buit. L'aplicació és a `app/` i `requirements.txt` és a l'arrel del repositori.
5. Railway llegeix `railway.json`. La construcció instal·la `requirements.txt` i l'inici és `uvicorn app.main:app --host 0.0.0.0 --port $PORT --workers 2`.

Si Railway et demana un `Root Directory`, no n'hi posis cap. El repositori ja és el projecte.

## 2. Configurar `SESSION_SECRET`

`SESSION_SECRET` és obligatori. Sense aquesta variable, `app/main.py` falla en importar i el desplegament no arriba a estar sa.

Genera'n un:

```bash
python -c 'import secrets; print(secrets.token_urlsafe(48))'
```

Afegeix-lo a les variables del servei. No el canviïs sense motiu. Si canvia, els testimonis d'accés signats abans deixen de valer. Els testimonis de refresc es guarden a la base i no depenen d'aquest secret: si encara són vàlids, el client pot demanar un testimoni d'accés nou sense tornar a iniciar sessió.

## 3. Comprovar el volum

`railway.json` declara un volum anomenat `vault-data` muntat a `/data`. Comprova que el servei el té i que el punt de muntatge és `/data`. La base és `/data/vaults.db`.

Si el volum no està muntat, la base pot acabar dins del contenidor i es perd al següent desplegament. Per a un servei real, el volum no és opcional.

El codi fa una còpia `vaults.db.bak-<timestamp>` abans de migrar una base antiga. Aquesta còpia també ha de viure al volum.

## 4. Desplegar i comprovar

Quan el desplegament acabi, prova la comprovació de salut:

```bash
curl -sS https://<el-teu-projecte>.up.railway.app/healthz
```

Ha de respondre `200` amb aquest JSON:

```json
{
  "status": "ok",
  "service": "SherLock Cloud API (Railway)",
  "version": "1.1.0"
}
```

Si reps un `502` o la comprovació de salut falla, mira els logs del servei abans de tocar res. Les causes habituals són `SESSION_SECRET` absent, un error en instal·lar les dependències o un problema amb el port.

Railway pot encuar o trigar el desplegament, sobretot en el pla gratuït. No hi ha una franja horària garantida; si el desplegament no arrenca, revisa l'estat i els logs abans de tornar a prémer el botó.

## 5. Variables d'entorn

| Variable | Valor | Per a què |
| --- | --- | --- |
| `SESSION_SECRET` | obligatori | Signa els JWT. |
| `DB_DIR` | `/data` si existeix; si no, el directori actual | Directori de `vaults.db`. |
| `TRUST_PROXY` | `1` darrere del proxy de Railway | Fa servir `X-Forwarded-For` per als límits de peticions. |
| `MAX_BLOB_BYTES` | `10485760` | Mida màxima del blob xifrat, 10 MB. |
| `MAX_REQUEST_BODY_SIZE` | `12582912` | Mida màxima del cos HTTP, 12 MB. |
| `CORS_ORIGINS` | buit | Llista separada per comes. Si és buida no s'afegeix CORS. |

`TRUST_PROXY` només té sentit si el proxy és de confiança. El codi agafa l'última adreça de `X-Forwarded-For`, no la primera.

## 6. Actualitzacions

Puja els canvis a `main` i Railway torna a desplegar. Si el projecte no té el desplegament automàtic activat, llança'l des del botó de desplegament o amb `railway up` si tens la CLI enllaçada al projecte.

Després de cada desplegament, comprova `/healthz`. Si el canvi toca l'esquema, el codi fa una còpia abans de migrar i després crida `init_db()`. El volum no es versiona sol; abans d'un canvi gran, baixa una còpia de `vaults.db`.

## 7. Logs i problemes habituals

- `RuntimeError: SESSION_SECRET must be configured before starting the cloud API`: falta la variable o el servei no l'ha agafat.
- La base no es pot escriure: el volum no està muntat a `/data` o els permisos no són correctes.
- `pip install` falla: revisa `requirements.txt` i la versió de Python que fa servir Nixpacks.
- Un `502` poc després del desplegament pot ser que el procés encara estigui arrencant. Espera uns segons i torna a provar.

Els logs i les mètriques són al panell del servei. Per a un problema d'autenticació, comprova primer que el client crida l'URL correcta i que el `SESSION_SECRET` no ha canviat.

## 8. Docker (opcional)

Si vols provar la imatge en local:

```bash
docker build -t password-manager-cloud .

docker run --rm -p 8000:8000 \
  -e SESSION_SECRET="$(python -c 'import secrets; print(secrets.token_urlsafe(48))')" \
  -v "$PWD/data:/data" \
  password-manager-cloud
```

El `Dockerfile` exposa el port 8000 i arrenca uvicorn amb dos processos. A Railway, el desplegament normal fa servir Nixpacks i `$PORT`; la imatge Docker només cal si la vols executar fora de Railway.

## 9. Endpoints

La referència completa és a [README.md](README.md). Les rutes que fa servir l'app són:

- `POST /v1/auth/register`, `/v1/auth/login`, `/v1/auth/refresh`, `/v1/auth/logout`
- `GET` i `DELETE /v1/auth/me`
- `GET` i `PUT /v1/vault`
- `GET /healthz`

Les rutes amb `vault_id` explícit segueixen al servidor per als clients que ja el guarden, però el flux nou no les necessita.
