# Unicode, reserved names i confusable policy v1

## Identyfikator bezpieczeństwa

Canonical handle jest wyłącznie ASCII `[a-z0-9_]{3,24}`. Wielkie litery są
nielegalne, więc case folding nie tworzy alternatywnego identyfikatora. Nazwa
pliku musi być identyczna z handle.

Policy v1 rezerwuje:

```text
admin administrator moderator mod owner root server system support
sunderfront standalonethewalls thewalls
```

## Confusable skeleton

Policy v1 używa danych Unicode Security Mechanisms, Unicode 17.0.0. Repo zawiera
minimalny, przypięty wyciąg mapowań istotnych dla dozwolonego alfabetu w:

```text
src/main/resources/unicode/confusables-ascii-v17.0.0.txt
```

SHA-256 pełnego źródłowego `confusables.txt` użytego do wygenerowania wyciągu:

```text
091c7f82fc39ef208faf8f94d29c244de99254675e09de163160c810d13ef22a
```

Algorytm dla handle:

1. NFD;
2. zamiana każdego code point według przypiętej tabeli UTS #39;
3. NFD;
4. lowercase `Locale.ROOT`.

Dwa różne handle z tym samym skeleton są odrzucane. Test vector:

```text
modern  -> rnodern
rn0dern -> rnodern
```

Ta para koliduje. `player_one` pozostaje stabilny. Nie ma własnego algorytmu
„na oko”; reguła i dane są wersjonowane razem.

## Display name

`displayName` jest wyłącznie prezentacyjny i nigdy nie uczestniczy w autoryzacji
lub unikalności. Jest opcjonalny i musi:

- być już NFC;
- mieć 1..32 code points i najwyżej 128 UTF-8 bytes;
- nie mieć edge whitespace;
- nie zawierać control, format/bidi controls, private-use, surrogate, unassigned,
  line separator ani paragraph separator code points.

Snapshot v1 nie zawiera display name, ponieważ strict parser konsumenta nie
akceptuje nieznanych pól.

## Aktualizacja Unicode

Aktualizacja wymaga osobnego issue/PR, nowego pliku danych, test vectors i
zwiększenia `policyVersion`. Przed zmianą należy uruchomić nową politykę na
wszystkich istniejących claimach i jawnie raportować nowe kolizje. Istniejące
claimy i immutable releases nie są po cichu reinterpretowane. Migracja musi
określić, które claimy zachowują stan i jak rozwiązać nową kolizję przez review.
