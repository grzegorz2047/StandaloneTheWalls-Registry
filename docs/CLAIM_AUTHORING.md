# Przygotowanie claimu, rotacji i revoke

Prywatny player key pozostaje lokalny. Nie wklejaj go do issue, PR, commita,
workflow input ani logu.

Poniżej użyto OpenSSL 3 jako lokalnego narzędzia. Klucz musi być dedykowany grze,
nie SSH/PGP/krypto/login key.

## 1. Wygeneruj klucz i publiczne SPKI

```bash
openssl genpkey -algorithm ED25519 -out player-private.pem
PUBLIC_KEY=$(openssl pkey -in player-private.pem -pubout -outform DER | openssl base64 -A)
PLAYER_ID=$(./gradlew -q run --args="player-id $PUBLIC_KEY")
HANDLE=example_player
PREFIX=$(./gradlew -q run --args="prefix $HANDLE")
mkdir -p "claims/$PREFIX"
```

Zabezpiecz `player-private.pem` lokalnie i wykonaj zaszyfrowany backup. Repo nie
implementuje odzyskania utraconego klucza.

## 2. Zbuduj unsigned canonical claim

Utwórz plik z pustym polem podpisu, a następnie canonicalizuj go:

```json
{"handle":"example_player","operations":[{"displayName":"Example Player","operation":"CLAIM","playerId":"sf1_...","publicKey":"BASE64_SPKI","sequence":1,"signature":"","version":1}],"policyVersion":1,"schema":1}
```

```bash
./gradlew -q run --args="canonicalize draft.json claims/$PREFIX/$HANDLE.json"
./gradlew -q run --args="transcript claims claims/$PREFIX/$HANDLE.json 0 transcript.bin"
SIGNATURE=$(openssl pkeyutl -sign -rawin -inkey player-private.pem -in transcript.bin | openssl base64 -A)
```

Wstaw `SIGNATURE` do pola `signature`, ponownie canonicalizuj finalny plik i
uruchom:

```bash
./gradlew -q run --args="validate claims"
```

Nie commituj `draft.json`, `transcript.bin`, prywatnego klucza ani lokalnych
backupów.

## Rotacja player key

1. Wygeneruj nowy dedykowany Ed25519 key i wyprowadź nowy `playerId`.
2. Dopisz `ROTATE` z kolejnym `sequence` do tego samego pliku.
3. Z pustymi `oldSignature` i `newSignature` canonicalizuj plik.
4. Wygeneruj jeden transcript dla indeksu nowej operacji.
5. Podpisz dokładnie ten sam plik `transcript.bin` starym i nowym kluczem.
6. Wstaw oba podpisy, canonicalizuj i waliduj.

Rotacja nie działa po revoke i nie zastępuje recovery utraconego starego klucza.

## Zmiana display name

Dopisz `SET_DISPLAY_NAME` z aktualnym `playerId`, kolejnym `sequence` i podpisem
aktualnego klucza. Handle pozostaje niezmienny.

## Revoke

Dopisz `REVOKE` z aktualnym `playerId`, kolejnym `sequence` i podpisem aktualnego
klucza. Revoke jest publiczny, terminalny i nie uwalnia handle.

## Pull request

PR powinien zmieniać tylko jeden claim history i dokumentować zamierzoną
operację. Review właściciela rejestru jest obowiązkowe, ale review nie zastępuje
kryptograficznego dowodu właściciela.
