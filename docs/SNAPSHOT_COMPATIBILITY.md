# Dowód zgodności snapshotu v1

Generator jest podporządkowany istniejącemu konsumentowi, przypiętemu do:

```text
grzegorz2047/StandaloneTheWalls@ed45d58db9a0b883ea1f7284324a205f33f16cba
```

Nie używa `main` ani `latest` jako dowodu kompatybilności.

## Exact schema

`registry-v1.json` zawiera dokładnie top-level:

```text
entries, generatedAt, rootKeyId, schema, sequence
```

Entry zawiera dokładnie:

```text
handle, playerId, publicKey, status
```

`status` to `ACTIVE` albo `REVOKED`. Entries są ściśle rosnące po canonical
handle. `generatedAt` jest dokładnym `Instant.toString()`. `rootKeyId` to:

```text
"sfr1_" + lowercase-base32-no-padding(sha256(canonical root Ed25519 SPKI))
```

Detached digest to SHA-256 dokładnych JSON bytes zapisany lowercase hex. Detached
Ed25519 signature obejmuje dokładne JSON bytes, nie digest.

## Publiczny vector

Dla publicznego klucza:

```text
MCowBQYDK2VwAyEAoBGdJyYRGPquhsJXoEoTOOticDHR4bM2z/5DScGCHPU=
```

oraz sequence `7`, `generatedAt=2026-08-02T00:00:00Z`, handle `player_one`,
status `ACTIVE`, generator emituje dokładnie 333 bajty, bez końcowego LF. SHA-256:

```text
f160bf701d0e1291d50f958ac55941cc2fb63a4e9807ef9c847582affd9e3899
```

Repo przechowuje exact bytes w `src/test/resources/snapshot-v1-vector.json`.

## CI proof

Job `consumer-compatibility`:

1. checkoutuje konsumenta na powyższym immutable commit SHA;
2. porównuje publiczny vector byte-for-byte;
3. uruchamia jego istniejące `RegistrySnapshotJsonCodecTest` i
   `RegistrySnapshotVerifierTest`.

Lokalne testy dodatkowo zmieniają jeden bajt JSON, digest i signature oraz
sprawdzają unknown root. Generator nie kopiuje parsera konsumenta jako nowego
kontraktu; zgodność jest dowodzona wspólnym publicznym vectorem i realnymi testami
konsumenta.
