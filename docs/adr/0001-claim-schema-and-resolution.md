# ADR 0001: Claim schema v1 i deterministyczne rozwiązywanie historii

- Status: Accepted
- Data: 2026-08-02
- Issue: #1
- Konsument: `grzegorz2047/StandaloneTheWalls@ed45d58db9a0b883ea1f7284324a205f33f16cba`

## Decyzja

Jeden plik reprezentuje całą, append-only historię jednego handle:

```text
claims/<prefix>/<canonical-handle>.json
```

`canonical-handle` pasuje do `[a-z0-9_]{3,24}`. Prefix to dwie małe cyfry
szesnastkowe pierwszego bajtu:

```text
sha256(UTF-8(canonical-handle))[0]
```

Przykład prefixu wylicza komenda `prefix`. Parser wymaga dokładnie dwóch
segmentów, zgodności ścieżki z polem `handle`, regularnego pliku i braku symlinków.

## Root claim object

Top-level object zawiera dokładnie:

| Pole | Reguła |
|---|---|
| `handle` | canonical ASCII handle |
| `operations` | 1..128 operacji w kolejności sekwencji |
| `policyVersion` | integer `1` |
| `schema` | integer `1` |

Repozytorium dopuszcza najwyżej 10 000 claim files. Jeden plik ma 1..65 536
bajtów. JSON ma maksymalną głębokość 8 i string długości do 4096 UTF-16 code
units. Dozwolone liczby są wyłącznie signed 64-bit integers.

## Operacje

Każda operacja ma `version: 1` i dodatni `sequence`. Pierwsza sekwencja to `1`,
a kolejne zwiększają ją dokładnie o jeden.

### `CLAIM`

Dokładne pola:

```json
{"displayName":null,"operation":"CLAIM","playerId":"sf1_...","publicKey":"BASE64_SPKI","sequence":1,"signature":"BASE64_SIGNATURE","version":1}
```

Jest legalna wyłącznie jako pierwsza operacja. `playerId` musi być równy:

```text
"sf1_" + lowercase-base32-no-padding(sha256(canonical Ed25519 X.509 SPKI))
```

Podpis jest weryfikowany kluczem zadeklarowanym w tej operacji.

### `ROTATE`

Dokładne pola:

```json
{"displayName":null,"newPlayerId":"sf1_...","newPublicKey":"BASE64_NEW_SPKI","newSignature":"BASE64_NEW_SIGNATURE","oldSignature":"BASE64_OLD_SIGNATURE","operation":"ROTATE","previousPlayerId":"sf1_...","sequence":2,"version":1}
```

`previousPlayerId` musi być aktualnym ID. Nowy ID musi wynikać z nowego SPKI i
musi różnić się od starego. Ten sam transcript podpisują stary oraz nowy klucz.
Brak któregokolwiek podpisu kończy walidację fail-closed.

### `SET_DISPLAY_NAME`

Dokładne pola:

```json
{"displayName":"Presentation Name","operation":"SET_DISPLAY_NAME","playerId":"sf1_...","sequence":2,"signature":"BASE64_SIGNATURE","version":1}
```

Operację podpisuje aktualny klucz. `displayName` może być `null`; nie jest
identyfikatorem ani polem snapshotu v1.

### `REVOKE`

Dokładne pola:

```json
{"operation":"REVOKE","playerId":"sf1_...","sequence":2,"signature":"BASE64_SIGNATURE","version":1}
```

Operację podpisuje aktualny klucz. Stan `REVOKED` jest terminalny: schema v1 nie
pozwala ponownie aktywować, rotować ani modyfikować handle. Utrata klucza nie
uruchamia automatycznego recovery i nie zwalnia nazwy. Ewentualny recovery wymaga
nowego, jawnie zaprojektowanego schematu i review; nie może udawać zwykłej
rotacji kryptograficznej.

## Canonical transcript

Dla każdej operacji usuwa się pola `signature`, `oldSignature` i `newSignature`.
Podpisane bytes to RFC 8785/JCS encoding dokładnie tego obiektu:

```json
{"handle":"canonical_handle","operation":{...operacja bez podpisów...},"policyVersion":1,"schema":1}
```

Podpis nie obejmuje siebie, ale obejmuje handle, typ, wersję, sekwencję i każde
pole semantyczne operacji. Ed25519 signature ma dokładnie 64 bajty i jest
kodowany canonical padded Base64.

## Parser i canonical JSON

Parser:

- dekoduje UTF-8 z `REPORT`, bez replacement characters;
- odrzuca duplicate keys, unknown fields, missing fields i trailing data;
- odrzuca whitespace, inną kolejność pól, niekanoniczne escapes i liczby przez
  porównanie input bytes z ponownym JCS encodingiem;
- odrzuca invalid/non-Ed25519 lub niekanoniczne X.509 SPKI;
- nigdy nie sortuje ani nie naprawia dostarczonej historii.

## Deterministyczne rozwiązywanie

Filesystem order nie ma znaczenia. Ścieżki są zamieniane na portable `/`,
sortowane leksykograficznie, a finalne entries ponownie sortowane po handle.

Fail-closed są między innymi:

- dwa pliki dla jednego handle;
- dwa handle o tym samym policy-v1 skeleton;
- luka, duplikat lub zmiana kolejności `sequence`;
- operacja przed `CLAIM`;
- drugi `CLAIM`;
- zły podpis lub `playerId`;
- operacja po `REVOKE`.

Wynik zawiera zarówno `ACTIVE`, jak i `REVOKED`, aby revoke nie zwalniał handle.
