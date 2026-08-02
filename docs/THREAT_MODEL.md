# Threat model

## Chronione aktywa

- binding `canonical handle -> playerId/publicKey/status`;
- prywatne player keys;
- prywatny registry root key;
- monotoniczna historia i exact snapshot bytes;
- last-known-good snapshot po stronie serwera.

## Granice zaufania

- claim JSON i pull request są niezaufanym inputem;
- GitHub account/PR author/branch/commit signature nie są tożsamością gracza;
- CI runner w PR nie otrzymuje root secret;
- release runner uzyskuje secret dopiero po ochronie environment;
- GitHub Release/HTTPS są transportem, nie trust anchor;
- serwer ufa wyłącznie lokalnie skonfigurowanym publicznym rootom i verifierowi.

## Ataki i zabezpieczenia

| Atak | Zabezpieczenie |
|---|---|
| Claim cudzym handle bez klucza | Ed25519 signature nad canonical transcript |
| Podmiana public key przy zachowaniu `playerId` | ponowne wyprowadzenie `playerId` z canonical SPKI |
| Niekanoniczny/ambiguous JSON | strict UTF-8, duplicate detection, exact JCS byte equality |
| Unknown field parser differential | exact allow-list pól i brak trailing data |
| Filesystem-order nondeterminism | portable path sort i final handle sort |
| Duplicate/confusable handle | one-history rule, ASCII handle, policy-v1 skeleton collision |
| Przejęcie podczas rotacji | podpis starego i nowego klucza nad tym samym transcript |
| Reuse revoked handle | terminalny `REVOKE`; entry pozostaje w snapshotcie |
| Root secret exfiltration przez PR | read-only PR workflow bez environment secret |
| Root secret w logu/cache | secret tylko jako env, brak echo/cache/debug artifacts, repo scan |
| Częściowe wydanie | draft release, asset-count check, cleanup on error |
| Mutable release/rollback | immutable semver tag, no overwrite, no latest, monotonic sequence |
| Nieznany root w artefakcie | lokalny trust bundle; artifact nie ustanawia zaufania |
| Złośliwa aktualizacja Unicode | pinned version/hash, policyVersion bump i collision migration |
| Symlink/specjalny plik | NOFOLLOW, regular-file checks, bounded reads |

## Pozostałe ryzyka poza PR-em

- poprawna konfiguracja branch ruleset i environment pozostaje operacją właściciela;
- GitHub i runner są częścią build/release supply chain, choć actions i zależności są przypięte;
- ten PR nie implementuje serwerowego fetch/cache/scheduler ani jego rollback policy;
- schema v1 nie odzyskuje utraconego player key;
- manualny operator może zatwierdzić społecznie niepożądany, ale kryptograficznie
  poprawny claim; review i reserved policy ograniczają, lecz nie eliminują tego ryzyka;
- nie przeprowadzono zewnętrznego audytu kryptograficznego.
