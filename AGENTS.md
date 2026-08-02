# Instrukcje dla agentów i contributorów

Te reguły są obowiązkowe dla każdej zmiany.

1. Jeden issue na jeden PR. Nie mieszaj refaktorów ani zmian konsumenta.
2. Przeczytaj README, właściwy ADR, threat model i przypięty kontrakt konsumenta.
3. Nigdy nie commituj sekretów, prywatnych kluczy, seedów, recovery material ani danych użytkownika.
4. Claim jest autoryzowany wyłącznie przez poprawny podpis application-specific Ed25519 player key.
5. Autor PR-a, konto GitHub, branch i commit signature nie są dowodem tożsamości gracza.
6. Claimy i snapshoty muszą być strict UTF-8, exact RFC 8785/JCS i deterministyczne na Windows oraz Linux.
7. Nie zmieniaj snapshot schema v1 dla wygody generatora. Zgodność z przypiętym konsumentem musi być dowiedziona testem.
8. Nie dodawaj prywatnych kluczy do fixtures. Testy generują wyłącznie ephemeral Ed25519 keys.
9. Rotacja player key wymaga podpisu starego i nowego klucza. Revoke jest terminalny w schema v1.
10. Nie reinterpretuj istniejących claimów po zmianie Unicode. Zwiększ `policyVersion`, opisz migrację i sprawdź kolizje.
11. Release assets są immutable. Nie używaj ani nie publikuj mutable `latest` jako kontraktu.
12. PR CI jest read-only i nie może otrzymać produkcyjnego root key.
13. Root signing występuje wyłącznie w chronionym environment i nad dokładnymi bajtami finalnego JSON.
14. CODEOWNERS nie zastępuje branch protection; wymagane ustawienia są w `docs/GOVERNANCE.md`.
15. Uruchom `./gradlew check`, walidację claimów i test konsumenta. W PR wpisz dokładnie, co wykonano i czego nie wykonano.
16. Nie rozszerzaj zakresu o HTTPS provider, cache SFRB, scheduler, klienta gry, konta, OAuth, e-mail, hasła ani backend webowy.
