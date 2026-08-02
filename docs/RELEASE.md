# Chronione wydanie podpisanego snapshotu

## PR CI

`.github/workflows/ci.yml` ma wyłącznie `contents: read` i nie odwołuje się do
produkcyjnego root secret. Wykonuje:

- build Java 21 z `-Xlint:all -Werror`;
- JUnit, JaCoCo, format/source policy i secret scan;
- strict claim validation;
- powtórzony test deterministycznego wyniku;
- test kompatybilności z przypiętym konsumentem.

Testy używają ephemeral Ed25519 keys.

## Release workflow

`.github/workflows/release.yml` jest wyłącznie `workflow_dispatch`, ma minimalne
`contents: write` i korzysta z environment `registry-production`. Environment
musi mieć wymagane review, deployment branch tylko `main` i secret:

```text
REGISTRY_ROOT_PRIVATE_KEY_PKCS8_B64
```

Secret jest canonical padded Base64 PKCS#8 Ed25519. Workflow nie drukuje go, nie
cache'uje i nie publikuje. Jawny root X.509 SPKI jest inputem i musi odpowiadać
prywatnemu kluczowi.

Inputy:

- immutable tag `registry-vMAJOR.MINOR.PATCH`;
- monotonic non-negative `sequence`;
- canonical UTC `generated_at`;
- aktywny root public SPKI;
- opcjonalne overlap root SPKI, po jednym Base64 na linię.

## Procedura

1. Wybierz workflow z default branch `main` i podaj inputy.
2. Reviewer environment sprawdza commit SHA, root ID, sequence i overlap plan.
3. Workflow odrzuca istniejący tag lub release.
4. Z czystego checkoutu ponownie uruchamia pełne `clean check` i claim validation.
5. Buduje exact snapshot bytes i digest.
6. Wczytuje secret; brak sekretu kończy run przed publikacją.
7. Podpisuje exact JSON bytes, sprawdza podpis odpowiadającym publicznym rootem.
8. Weryfikuje snapshot, digest, signature i canonical public trust bundle.
9. Tworzy draft release z pięcioma assets.
10. Sprawdza kompletny asset count i dopiero wtedy publikuje release.
11. Przy błędzie usuwa draft i utworzony tag, aby nie pozostawić częściowego zestawu.

Workflow nie nadpisuje istniejącego tagu/release i ustawia `--latest=false`.

## Assets

- `registry-v1.json`: exact JCS bytes;
- `registry-v1.sha256`: lowercase SHA-256 plus LF;
- `registry-v1.sig`: padded Base64 64-byte Ed25519 signature plus LF;
- `registry-trust-v1.json`: public ACTIVE/OVERLAP roots, canonical SPKI i derived IDs;
- `registry-manifest-v1.json`: sequence, time, root ID, digest i nazwy assets.

## Konsumpcja

Serwer powinien używać immutable release URL/tag, oczekiwanego rozmiaru/hash i
lokalnego `RegistryTrustBundle`. Sam plik publicznego trust bundle nie jest
automatycznym źródłem zaufania; operator musi jawnie zainstalować zaakceptowane
rooty. Nie używać ruchomego `latest`.
