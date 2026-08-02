# Wymagane ustawienia GitHub governance

Pliki repozytorium nie mogą samodzielnie wymusić poniższych ustawień. Właściciel
musi skonfigurować je w GitHub Settings. Sama obecność CODEOWNERS nie włącza
branch protection.

## Ruleset dla `main`

Utwórz active branch ruleset dla `main`:

- require pull request before merging;
- minimum 1 approval;
- require review from Code Owners;
- dismiss stale approvals on new commits;
- require approval of the most recent reviewable push;
- require all conversations resolved;
- require status checks `validate` i `consumer-compatibility`;
- require branches to be up to date before merging;
- block force pushes;
- block deletions;
- restrict direct updates do właściciela tylko przez PR;
- do not allow bypass poza jawnie wskazanym awaryjnym administratorem.

Merge queue nie jest wymagana. Auto-merge nie powinien omijać CODEOWNERS.

## CODEOWNERS

`.github/CODEOWNERS` wskazuje `@grzegorz2047` dla claimów, polityk, workflow,
trust/release docs i kodu. Wymagany review właściciela jest ustawieniem ruleset,
nie efektem samego pliku.

## Environment `registry-production`

- required reviewer: właściciel rejestru;
- prevent self-review, jeżeli plan GitHub udostępnia tę opcję;
- deployment branches/tags: wyłącznie `main` jako źródło workflow;
- secret `REGISTRY_ROOT_PRIVATE_KEY_PKCS8_B64` tylko tutaj;
- brak secretu na poziomie repo/org dostępnego dla PR;
- opcjonalny wait timer jako drugi bezpiecznik;
- administratorzy nie omijają protection podczas normalnego wydania.

Reviewer porównuje dispatch commit z `main`, sequence, root IDs i plan overlap.

## Tag ruleset `registry-v*`

- block update istniejącego tagu;
- block deletion;
- creation dozwolone wyłącznie chronionemu release workflow/bypass actor;
- żadnego ręcznego retargetowania tagu.

## Actions

- wymagaj actions przypiętych do pełnego commit SHA;
- ogranicz do GitHub-authored actions użytych w repo;
- nie zezwalaj fork PR na dostęp do write tokenów lub environment secrets;
- pozostaw domyślne `GITHUB_TOKEN` read-only, z wyjątkiem jawnego
  `contents: write` w release workflow.

## Review claimu

Reviewer sprawdza zakres jednego handle, wynik CI, zamierzoną operację, brak
sekretów i brak zmian workflow/polityki w zwykłym claim PR. Kryptograficzna
walidacja jest obowiązkowa niezależnie od społecznego review.
