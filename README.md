# StandaloneTheWalls Registry

Publiczny, reprodukowalny rejestr globalnych canonical handle dla gry
[StandaloneTheWalls](https://github.com/grzegorz2047/StandaloneTheWalls).
Gracze proponują samopodpisane historie claimów przez pull request. CI sprawdza
prawo do klucza gracza, rozwiązuje historie deterministycznie i dowodzi zgodności
snapshotu v1 z przypiętym konsumentem. Chroniony workflow wydania podpisuje
wyłącznie dokładne bajty snapshotu kluczem głównym rejestru i publikuje
niezmienny zestaw GitHub Release assets.

Konto GitHub, autor PR-a, nazwa brancha ani podpis commita nie są dowodem
tożsamości w grze.

## Granice

Repozytorium implementuje authoring i publikację rejestru. Nie implementuje
serwerowego pobierania HTTPS, cache SFRB, schedulerów, logowania gracza, kont,
OAuth, e-maili, haseł ani automatycznego zatwierdzania claimów.

## Kontrakty

- claim schema v1: [`docs/adr/0001-claim-schema-and-resolution.md`](docs/adr/0001-claim-schema-and-resolution.md);
- przygotowanie, rotacja i revoke: [`docs/CLAIM_AUTHORING.md`](docs/CLAIM_AUTHORING.md);
- Unicode/confusable policy v1: [`docs/UNICODE_POLICY.md`](docs/UNICODE_POLICY.md);
- zgodność snapshotu: [`docs/SNAPSHOT_COMPATIBILITY.md`](docs/SNAPSHOT_COMPATIBILITY.md);
- wydanie i uprawnienia: [`docs/RELEASE.md`](docs/RELEASE.md);
- root rotation: [`docs/ROOT_ROTATION.md`](docs/ROOT_ROTATION.md);
- threat model: [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md);
- ustawienia repozytorium: [`docs/GOVERNANCE.md`](docs/GOVERNANCE.md).

## Toolchain

Wymagane jest JDK 21. `gradlew` uruchamia oficjalny Gradle Wrapper 9.6.1. JAR
wrappera jest pobierany z przypiętego commita konsumenta i akceptowany wyłącznie
po porównaniu SHA-256; dystrybucja Gradle ma osobny przypięty checksum. Zależności
są objęte strict dependency locking i Gradle dependency verification z SHA-256.

```bash
./gradlew --no-daemon check
mkdir -p claims
./gradlew --no-daemon run --args="validate claims"
```

Przydatne komendy:

```bash
./gradlew -q run --args="prefix canonical_handle"
./gradlew -q run --args="player-id BASE64_ED25519_SPKI"
./gradlew -q run --args="root-id BASE64_ED25519_SPKI"
./gradlew -q run --args="canonicalize input.json output.json"
./gradlew -q run --args="transcript claims claims/ab/canonical_handle.json 0 transcript.bin"
```

## Artefakty wydania

Każde wydanie publikuje dokładnie:

- `registry-v1.json`;
- `registry-v1.sha256`;
- `registry-v1.sig`;
- `registry-trust-v1.json`;
- `registry-manifest-v1.json`.

Nie istnieje kontrakt `latest`. Konsument wskazuje niezmienny tag/URL, oczekiwany
hash i lokalnie skonfigurowany trust bundle.
