# Configuració i proves de l'API

La guia principal és [README.md](README.md). Aquest fitxer només recull els
passos per provar l'API des de la línia d'ordres.

## 1. Variables d'entorn

```bash
export SESSION_SECRET="$(python -c 'import secrets; print(secrets.token_urlsafe(48))')"
export DB_DIR="$(mktemp -d)"
```

En producció, `SESSION_SECRET` ha de ser estable entre desplegaments. Si el
canvies, totes les sessions existents queden invalidades.

## 2. Crear un compte

```bash
curl -sS -X POST "$CLOUD_URL/v1/auth/register" \
  -H "Content-Type: application/json" \
  -d '{"username":"prova","password":"una-contrasenya-llarga"}'
```

La resposta inclou `access_token`, `refresh_token` i `vault_id`. Desa els dos
tokens; el client de l'app ho fa automàticament i mai no exposa el refresh
token al frontend.

## 3. Iniciar sessió

```bash
curl -sS -X POST "$CLOUD_URL/v1/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"prova","password":"una-contrasenya-llarga"}'
```

## 4. Renovar l'access token

L'access token dura 15 minuts. El client en demana un de nou amb el refresh
token abans de cada operació:

```bash
curl -sS -X POST "$CLOUD_URL/v1/auth/refresh" \
  -H "Content-Type: application/json" \
  -d '{"refresh_token":"<refresh_token>"}'
```

## 5. Pujar i baixar la caixa

El `blob` és el JSON xifrat que genera l'app (`salt`, `nonce`, `ciphertext`,
`version`). El servidor en valida l'estructura però no el desxifra.

```bash
# Primera pujada: no cal expected_version
curl -sS -X PUT "$CLOUD_URL/v1/vault" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  --data-binary @vault-upload.json

# Actualització: expected_version és obligatori
curl -sS -X PUT "$CLOUD_URL/v1/vault" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"blob":"<blob-xifrat>","expected_version":1}'

# Descarregar
curl -sS "$CLOUD_URL/v1/vault" -H "Authorization: Bearer $ACCESS_TOKEN"
```

Si `expected_version` no coincideix, la resposta és `409`: baixa la caixa o
resol el conflicte abans de tornar a pujar.

## 6. Tancar sessió i eliminar el compte

```bash
curl -sS -X POST "$CLOUD_URL/v1/auth/logout" \
  -H "Content-Type: application/json" \
  -d '{"refresh_token":"<refresh_token>"}'

curl -sS -X DELETE "$CLOUD_URL/v1/auth/me" \
  -H "Authorization: Bearer $ACCESS_TOKEN"
```

`DELETE /v1/auth/me` elimina el compte, la caixa i tots els refresh tokens.
