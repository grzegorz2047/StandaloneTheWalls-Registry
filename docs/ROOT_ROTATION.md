# Registry root rotation

Model jest prostym, jawnie konfigurowanym zestawem Ed25519 roots zgodnym z
lokalnym `RegistryTrustBundle` konsumenta. Nie istnieje automatyczna PKI ani
mechanizm, w którym pobrany artefakt sam ustanawia nowy trust anchor.

## Identyfikator

```text
rootKeyId = "sfr1_" + lowercase-base32-no-padding(
    sha256(canonical Ed25519 X.509 SPKI)
)
```

`registry-trust-v1.json` ma schema `1`. Każdy root ma exact fields:

- `acceptedFromSequence`;
- `publicKey`;
- `rootKeyId` wyprowadzony ponownie z SPKI;
- `status`: `ACTIVE` lub `OVERLAP`.

Generator sortuje roots po ID, odrzuca duplikaty i wymaga, aby root podpisujący
snapshot był `ACTIVE`. Obsługiwany jest jeden ACTIVE i najwyżej siedem OVERLAP
roots w eksporcie wydania.

## Planowana rotacja old -> new

1. Wygeneruj `new` offline i zabezpiecz prywatny klucz w nowym/zmienionym
   chronionym environment secret. Nie usuwaj jeszcze `old`.
2. Opublikuj sequence `N` podpisaną `old`, podając publiczny `new` jako OVERLAP.
3. Operatorzy pobierają publiczny bundle z immutable release, niezależnie
   sprawdzają ID i jawnie dodają `new` do lokalnego trust bundle. Minimalna
   obsługiwana sequence pozostaje co najmniej `N`.
4. Po potwierdzonym rollout opublikuj sequence `N+1` podpisaną `new`, z `old` jako
   OVERLAP. Serwery z oboma rootami akceptują zmianę; rollback protection blokuje
   sequence poniżej lokalnego minimum.
5. Utrzymuj overlap przez zdefiniowane okno operacyjne. Usuń `old` z kolejnych
   publicznych bundle dopiero gdy wszyscy wspierani operatorzy mają `new` i
   minimum sequence co najmniej `N+1`.
6. Usuń stary prywatny secret zgodnie z procedurą bezpiecznego zniszczenia.

Kolejność „najpierw trust, potem nowy podpis” jest obowiązkowa. Snapshot podpisany
nieznanym rootem jest odrzucany nawet gdy sam zawiera jego publiczny klucz.

## Rollback i equivocation

Release sequence jest monotoniczna. Operator ustawia minimalną akceptowaną
sequence i zachowuje last-known-good artifact. Ten repozytorium nie może wymusić
lokalnej polityki serwera, dlatego release notes i manifest muszą podawać
sequence. Ten sam sequence nie powinien być nigdy publikowany z innymi bytes.
Immutable tag i zakaz nadpisania zapobiegają normalnej equivocation ścieżce.

## Awaryjny revoke root key

Gdy prywatny root mógł wyciec:

1. natychmiast wyłącz release environment/secret i wstrzymaj wydania;
2. udokumentuj ostatnią znaną dobrą sequence i hash;
3. utwórz nowy root offline;
4. przekaż operatorom nowy publiczny trust anchor niezależnym, uwierzytelnionym
   kanałem administracyjnym;
5. operatorzy jawnie usuwają compromised root, dodają nowy i ustawiają minimum
   sequence powyżej zagrożonego zakresu;
6. dopiero potem publikuj nowy immutable snapshot.

Jeżeli `old` jest skompromitowany, jego podpis nie stanowi wystarczającego dowodu
rotacji. Recovery jest świadomą zmianą lokalnej konfiguracji zaufania, nie
samoczynną aktualizacją z sieci.
