# StandaloneTheWalls Registry

Publiczny, przenośny rejestr globalnych canonical handle dla projektu [StandaloneTheWalls](https://github.com/grzegorz2047/StandaloneTheWalls).

Repozytorium ma przechowywać samopodpisane claimy graczy, deterministycznie budować podpisany snapshot rejestru oraz publikować niezmienne, wersjonowane artefakty możliwe do zweryfikowania offline przez serwer gry.

## Granice bezpieczeństwa

- Konto GitHub ani autor pull requestu nie są tożsamością gracza.
- Każdy claim musi dowodzić posiadania osobnego klucza Ed25519 używanego przez grę.
- Prywatne klucze graczy i prywatny klucz główny rejestru nigdy nie trafiają do repozytorium, logów ani artefaktów CI.
- Snapshoty muszą być deterministyczne, podpisane, wersjonowane i publikowane pod niezmiennym tagiem; konsumenci nie używają ruchomego `latest`.
- Format publikowanego snapshotu musi pozostać zgodny z konsumentem w `grzegorz2047/StandaloneTheWalls`.

Implementację śledzi `grzegorz2047/StandaloneTheWalls#30` oraz issue w tym repozytorium.
