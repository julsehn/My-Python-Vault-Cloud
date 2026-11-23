# Configuració i proves de l'API

[README.md](README.md) explica què fa el servei. Aquí tens el camí per provar-lo des de la línia d'ordres: arrencar-lo en local, crear un compte, pujar una caixa i esborrar el compte. Les mateixes ordres funcionen contra Railway; canvia `CLOUD_URL` i fes servir HTTPS.

## 1. Arrencar el servei en local

```bash
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt

export SESSION_SECRET="$(python -c 'import secrets; print(secrets.token_urlsafe(48))')"
export DB_DIR="$(mktemp -d)"
export CLOUD_URL="http://127.0.0.1:8000"

uvicorn app.main:app --reload --port 8000
```

`SESSION_SECRET` no pot quedar buit: l'aplicació peta en arrencar si no hi és. `DB_DIR` és on es crea `vaults.db`. Si no el defineixes i `/data` existeix, el codi fa servir `/data`; si no, el directori actual.

La terminal es queda ocupada mentre uvicorn corre. Obre'n una altra per a les proves:

```bash
export CLOUD_URL="http://127.0.0.1:8000"
```

Les respostes són JSON. Les ordres fan servir `jq` per llegir-les; si no el tens, instal·la'l o copia els camps a mà.

## 2. Crear un compte

```bash
AUTH=$(curl -sS -X POST "$CLOUD_URL/v1/auth/register" \
  -H "Content-Type: application/json" \
  -d '{"username":"prova","password":"una-contrasenya-llarga"}')

printf '%s\n' "$AUTH" | jq
ACCESS_TOKEN=$(printf '%s' "$AUTH" | jq -r .access_token)
REFRESH_TOKEN=$(printf '%s' "$AUTH" | jq -r .refresh_token)
```

Si tot va bé, la resposta és un `201` amb `user_id`, `username`, `email`, `access_token`, `refresh_token`, `vault_id` i `token_type`. `email` és opcional. Si reps un `409`, el nom d'usuari ja existeix; un `422` vol dir que el cos no passa la validació.

## 3. Iniciar sessió

```bash
AUTH=$(curl -sS -X POST "$CLOUD_URL/v1/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"prova","password":"una-contrasenya-llarga"}')

ACCESS_TOKEN=$(printf '%s' "$AUTH" | jq -r .access_token)
REFRESH_TOKEN=$(printf '%s' "$AUTH" | jq -r .refresh_token)
```

Si el nom o la contrasenya no són correctes, la resposta és `401`. El missatge no diu quin dels dos falla.

## 4. Renovar el testimoni d'accés

El testimoni d'accés dura 15 minuts. Quan caduca, les rutes amb `Bearer` tornen `401` amb `El token ha caducat`. Demana'n un de nou amb el de refresc:

```bash
AUTH=$(curl -sS -X POST "$CLOUD_URL/v1/auth/refresh" \
  -H "Content-Type: application/json" \
  -d "{\"refresh_token\":\"$REFRESH_TOKEN\"}")

ACCESS_TOKEN=$(printf '%s' "$AUTH" | jq -r .access_token)
```

La resposta torna el mateix `refresh_token` que has enviat. No el canviïs. El client de l'app renova el testimoni abans de cada operació de núvol.

## 5. Pujar i baixar la caixa

El `blob` és el JSON xifrat que genera l'app. El servidor en valida l'estructura i la mida, però no el desxifra. Un blob buit, massa curt, amb base64 dolent o amb un `version` que no és `"1"` torna `422`.

```bash
cat > vault-upload.json <<'JSON'
{
  "blob": "{\"version\":\"1\",\"salt\":\"...\",\"nonce\":\"...\",\"ciphertext\":\"...\"}"
}
JSON
```

Substitueix els `...` pel blob real. Amb els punts suspensius, el `PUT` tornarà `422` perquè el base64 no és vàlid. El servidor comprova que `salt`, `nonce` i `ciphertext` siguin base64 i que el sobre tingui el format esperat.

En un compte sense caixa, la primera pujada no porta `expected_version`:

```bash
UPLOAD=$(curl -sS -X PUT "$CLOUD_URL/v1/vault" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  --data-binary @vault-upload.json)

printf '%s\n' "$UPLOAD" | jq
VERSION=$(printf '%s' "$UPLOAD" | jq -r .version)
```

En un compte nou, això crea la versió 1. A partir d'aquí, cada `PUT` necessita `expected_version`:

```bash
jq --argjson v "$VERSION" '. + {expected_version: $v}' vault-upload.json > vault-update.json

curl -sS -X PUT "$CLOUD_URL/v1/vault" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  --data-binary @vault-update.json | jq
```

Si `expected_version` falta en una caixa que ja existeix, la resposta és `409`. Si és vella, també. Baixa la caixa, decideix quina versió vols i torna a pujar amb la versió actual.

Per descarregar-la:

```bash
curl -sS "$CLOUD_URL/v1/vault" \
  -H "Authorization: Bearer $ACCESS_TOKEN" | jq
```

Si el compte encara no ha pujat res, la resposta és `404`. No vol dir que el testimoni sigui dolent.

## 6. Tancar sessió o eliminar el compte

Són dues accions diferents. Tancar la sessió no esborra la caixa; eliminar el compte sí.

Per tancar la sessió:

```bash
curl -sS -o /dev/null -w '%{http_code}\n' -X POST "$CLOUD_URL/v1/auth/logout" \
  -H "Content-Type: application/json" \
  -d "{\"refresh_token\":\"$REFRESH_TOKEN\"}"
```

La resposta és `204`. Es revoquen tots els testimonis de refresc del compte i puja `token_version`, així que les altres sessions també cauen. El testimoni d'accés que acabes de fer servir deixa de valer.

Per eliminar el compte:

```bash
curl -sS -o /dev/null -w '%{http_code}\n' -X DELETE "$CLOUD_URL/v1/auth/me" \
  -H "Authorization: Bearer $ACCESS_TOKEN"
```

La resposta és `204`. S'eliminen el compte, la caixa i els testimonis de refresc. La còpia local no es toca.

Si el testimoni d'accés ha caducat, renova'l abans; si no, la resposta serà `401`.

Fes servir una via o l'altra. Si tanques la sessió primer, el testimoni d'accés queda invalidat i el `DELETE /v1/auth/me` et tornarà `401`; hauries de tornar a iniciar sessió. Si vols esborrar el compte, fes el `DELETE` directament.

## Quan alguna cosa falla

| Codi | Què sol passar |
| --- | --- |
| `400` | Format d'identificador de caixa incorrecte a les rutes explícites, o `Content-Length` invàlid. |
| `401` | Falta el `Bearer`, el testimoni ha caducat o s'ha revocat, o les credencials són dolentes. |
| `404` | El compte no té cap caixa, o la caixa no és d'aquest usuari. |
| `409` | Conflicte de versió, nom d'usuari ocupat o identificador de caixa en ús a les rutes explícites. |
| `411` | Has enviat un `POST` o `PUT` sense `Content-Length`. |
| `413` | El cos de la petició o el blob xifrat és massa gran. |
| `422` | El blob no té el format esperat, o el cos no passa la validació. |
| `429` | Massa intents d'autenticació. Espera abans de tornar-ho a provar. |

Els missatges d'error no inclouen el blob ni les contrasenyes.
