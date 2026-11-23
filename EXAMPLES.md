# Exemples d'ús

Exemples per parlar amb l'API des de fora de l'app. Tots fan servir el model de compte: un usuari, un JWT de 15 minuts i una caixa per compte. La caixa no té un `token` propi: el que la identifica és el compte i el `Bearer` de la sessió. El `blob` és el JSON xifrat que genera el client; el servidor el valida i el guarda, però no el pot desxifrar.

Les ordres necessiten `curl` i `jq`. Canvia `CLOUD_URL` per la URL del servei. Si encara no l'has arrencat en local, comença per [SETUP.md](SETUP.md).

```bash
export CLOUD_URL="http://127.0.0.1:8000"
```

## Flux complet amb curl

### 1. Registrar el compte

```bash
AUTH=$(curl -sS -X POST "$CLOUD_URL/v1/auth/register" \
  -H "Content-Type: application/json" \
  -d '{"username":"prova","password":"una-contrasenya-llarga"}')

printf '%s\n' "$AUTH" | jq
ACCESS_TOKEN=$(printf '%s' "$AUTH" | jq -r .access_token)
REFRESH_TOKEN=$(printf '%s' "$AUTH" | jq -r .refresh_token)
```

Respon `201` amb aquesta forma:

```json
{
  "user_id": 7,
  "username": "prova",
  "email": null,
  "access_token": "eyJhbGciOiJIUzI1NiIs...",
  "refresh_token": "...",
  "vault_id": "vault_...",
  "token_type": "bearer"
}
```

`vault_id` ja ve creat, però la caixa no existeix fins al primer `PUT`. No el generis tu; el servidor el crea i el guarda al compte. `email` és opcional.

### 2. Iniciar sessió

```bash
AUTH=$(curl -sS -X POST "$CLOUD_URL/v1/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"prova","password":"una-contrasenya-llarga"}')

ACCESS_TOKEN=$(printf '%s' "$AUTH" | jq -r .access_token)
REFRESH_TOKEN=$(printf '%s' "$AUTH" | jq -r .refresh_token)
```

Si el nom o la contrasenya no són correctes, la resposta és `401`. El servidor no diu quin dels dos camps falla.

### 3. Renovar el testimoni d'accés

El JWT dura 15 minuts. Quan caduca, les rutes amb `Bearer` tornen `401` amb `El token ha caducat`. Demana'n un de nou:

```bash
AUTH=$(curl -sS -X POST "$CLOUD_URL/v1/auth/refresh" \
  -H "Content-Type: application/json" \
  -d "{\"refresh_token\":\"$REFRESH_TOKEN\"}")

ACCESS_TOKEN=$(printf '%s' "$AUTH" | jq -r .access_token)
```

La resposta torna el mateix `refresh_token` que has enviat. No cal substituir-lo. Si el testimoni de refresc ha caducat o s'ha revocat, la resposta és `401` i toca tornar a iniciar sessió.

### 4. Comprovar l'estat del compte

```bash
curl -sS "$CLOUD_URL/v1/auth/me" \
  -H "Authorization: Bearer $ACCESS_TOKEN" | jq
```

La resposta té `user_id`, `username`, `email`, `vault_id`, `has_vault`, `vault_version` i `updated_at`. Un compte nou té `has_vault` a `false`, `vault_version` a `0` i `updated_at` a `null`.

### 5. Descarregar la caixa

```bash
curl -sS "$CLOUD_URL/v1/vault" \
  -H "Authorization: Bearer $ACCESS_TOKEN" | jq
```

Si encara no hi ha caixa, la resposta és `404` amb `Encara no hi ha cap SherLock desada per aquest usuari`. Quan n'hi ha, els camps són `vault_id`, `blob`, `version` i `updated_at`.

`version` és la revisió de la caixa al servidor. No el confonguis amb el `version` de dins del `blob`, que és el format del sobre xifrat i ara val `"1"`.

### 6. Pujar la caixa

Prepara el cos de la petició amb el blob xifrat:

```bash
BLOB='{"version":"1","salt":"...","nonce":"...","ciphertext":"..."}'
jq -n --arg blob "$BLOB" '{blob: $blob}' > vault-upload.json
```

Els `...` són llocs on va el contingut real. El servidor comprova que `salt` i `nonce` siguin base64 de la longitud correcta i que `ciphertext` no sigui massa curt. Si el blob no compleix aquestes comprovacions, la resposta serà `422`.

En un compte sense caixa, la primera pujada no porta `expected_version`:

```bash
UPLOAD=$(curl -sS -X PUT "$CLOUD_URL/v1/vault" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  --data-binary @vault-upload.json)

printf '%s\n' "$UPLOAD" | jq
VERSION=$(printf '%s' "$UPLOAD" | jq -r .version)
```

En un compte nou, això crea la versió 1. Per actualitzar, envia la versió que acabes de rebre:

```bash
jq --argjson v "$VERSION" '. + {expected_version: $v}' vault-upload.json > vault-update.json

curl -sS -X PUT "$CLOUD_URL/v1/vault" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  --data-binary @vault-update.json | jq
```

Si la caixa ja existeix i `expected_version` falta, la resposta és `409` amb `Cal la versió del núvol per sobreescriure una SherLock existent`. Si la versió és vella, també és `409`, però amb `Conflicte de versió: la SherLock ha canviat mentrestant`. Baixa la caixa, mira quina versió tens i torna a pujar amb la versió actual. No reintentis amb la mateixa.

### 7. Tancar la sessió

```bash
curl -sS -o /dev/null -w '%{http_code}\n' -X POST "$CLOUD_URL/v1/auth/logout" \
  -H "Content-Type: application/json" \
  -d "{\"refresh_token\":\"$REFRESH_TOKEN\"}"
```

Respon `204`. Es revoquen tots els testimonis de refresc del compte i puja `token_version`, així que la sessió cau també als altres dispositius. El testimoni d'accés actual deixa de valer. La caixa local no es toca.

### 8. Eliminar el compte

```bash
curl -sS -o /dev/null -w '%{http_code}\n' -X DELETE "$CLOUD_URL/v1/auth/me" \
  -H "Authorization: Bearer $ACCESS_TOKEN"
```

Respon `204`. S'eliminen el compte, la caixa i els testimonis de refresc. No cal esborrar la caixa abans. Si el testimoni d'accés ha caducat, renova'l primer; si no, la resposta serà `401`.

No tanquis la sessió i després facis el `DELETE` amb el mateix testimoni d'accés. Tancar la sessió invalida el testimoni i el `DELETE` et tornarà `401`. Tria una de les dues accions o torna a iniciar sessió.

## TypeScript

Un exemple curt amb `fetch`. No xifra res: el `blob` ha de venir del client que té la contrasenya mestra.

```ts
type Auth = {
  access_token: string;
  refresh_token: string;
};

type Vault = {
  vault_id: string;
  blob: string;
  version: number;
  updated_at: string;
};

const baseUrl = "https://<el-teu-projecte>.up.railway.app";

async function refresh(refreshToken: string): Promise<Auth> {
  const response = await fetch(`${baseUrl}/v1/auth/refresh`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ refresh_token: refreshToken }),
  });

  if (!response.ok) {
    throw new Error(`No s'ha pogut renovar la sessió: ${response.status}`);
  }

  return response.json();
}

async function saveVault(
  accessToken: string,
  blob: string,
  expectedVersion?: number,
): Promise<Vault | null> {
  const response = await fetch(`${baseUrl}/v1/vault`, {
    method: "PUT",
    headers: {
      Authorization: `Bearer ${accessToken}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      blob,
      expected_version: expectedVersion,
    }),
  });

  if (response.status === 409) {
    return null; // baixa la caixa i torna a provar amb la versió nova
  }

  if (!response.ok) {
    throw new Error(`Error en pujar la caixa: ${response.status}`);
  }

  return response.json();
}
```

`saveVault` sense `expectedVersion` serveix per a la primera pujada. En una caixa existent, passa-hi la versió que t'ha tornat l'últim `GET` o `PUT`.

## Errors comuns

| Codi | Què passa | Què fer |
| --- | --- | --- |
| `400` | `Content-Length` invàlid, o identificador de caixa amb format incorrecte en una ruta explícita. | Revisa la mida o el `vault_id` si fas servir una ruta explícita. |
| `401` | Falta el `Bearer`, el testimoni ha caducat o s'ha revocat, o les credencials són dolentes. | Si tens un testimoni de refresc, renova'n un d'accés. Si també falla o les credencials són dolentes, torna a iniciar sessió. |
| `404` | El compte no té caixa, o la caixa no és d'aquest usuari. | És normal abans de la primera pujada. Si la caixa existeix, mira que el testimoni sigui del compte correcte. |
| `409` | Conflicte de versió, nom d'usuari ocupat o identificador de caixa en ús en una ruta explícita. | Baixa la caixa i torna a pujar amb la versió actual. |
| `411` | Has enviat un `POST` o `PUT` sense `Content-Length`. | Fes servir `-d` o `--data-binary`; els clients que fan streaming han de declarar la mida. |
| `413` | El cos o el blob és massa gran. | El blob per defecte és de 10 MB i el cos de 12 MB. |
| `422` | El blob no té el format esperat, o el cos no passa la validació. | Comprova que el blob sigui el sobre xifrat sencer i que els camps siguin base64, o revisa els camps del compte. |
| `429` | Massa intents d'autenticació. | Espera abans de tornar-ho a provar. |

## Referència ràpida

| Mètode | Ruta | Autenticació | Resposta |
| --- | --- | --- | --- |
| `POST` | `/v1/auth/register` | cap | `201` amb el compte i els testimonis |
| `POST` | `/v1/auth/login` | cap | `200` amb el compte i els testimonis |
| `POST` | `/v1/auth/refresh` | `refresh_token` al cos | `200` amb un testimoni d'accés nou |
| `POST` | `/v1/auth/logout` | `refresh_token` al cos | `204` |
| `GET` | `/v1/auth/me` | `Bearer` | `200` amb el resum del compte |
| `DELETE` | `/v1/auth/me` | `Bearer` | `204` |
| `GET` | `/v1/vault` | `Bearer` | `200`, o `404` si encara no hi ha caixa |
| `PUT` | `/v1/vault` | `Bearer` | `200` amb la caixa desada |
| `GET` | `/v1/auth/check-username/{username}` | cap | `200` amb `available` |
