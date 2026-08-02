## Zakres

- Issue:
- Handle / operacja:
- Dlaczego zmiana jest ograniczona do jednego issue:

## Dowód claimu

- [ ] Claim jest exact canonical JSON.
- [ ] `playerId` wynika z canonical Ed25519 SPKI.
- [ ] Operacja ma wymagany podpis właściciela.
- [ ] Rotacja ma podpis starego i nowego klucza albo nie dotyczy.
- [ ] PR nie zawiera prywatnego klucza, seeda ani recovery material.
- [ ] Autor PR-a nie jest traktowany jako dowód tożsamości.

## Walidacja

```text
Wpisz dokładne komendy i wyniki.
```

## Zgodność i ryzyka

- [ ] Snapshot v1 nie dostał nowych pól.
- [ ] Nie użyto mutable `latest`.
- [ ] Pozostałe ryzyka / czego nie uruchomiono:
