# Laboratorijske vježbe 5

# **Online and Offline Password Guessing Attacks**

## Online Password Guessing

Otvaramo bash shell i *ping-amo* lab server kako bismo provjerili jesmo li na istoj lokalnoj mreži. Nakon toga, pomoću alata *nmap* provjeravamo koji su portovi otvoreni na računalu te otkrivamo što možemo potencijalno napadati. Naredbom 

```bash
nmap -v 10.0.15.0/28
```

provjeravamo 16 IP adresa te nam *nmap* daje informaciju koliko je *hostova* aktivno i da je na svima otvoren port 22 za SSH (Secure Shell). Kako bismo se mogli prijaviti na vlastiti SSH, moramo znati *password*, a budući da mi to ne znamo vršit ćemo *online* napad. Jedina informacija koju posjedujemo o *password-u* je ta da se sastoji od 4 do 6 znakova koji su svi mala slova engleske abecede što znači da postoji 26^4+26^5+26^6 kombinacija, odnosno 26^9.

Za otkrivanje *password-a* vršimo *brute force* napad i za to koristimo *hydra* alat te na taj način testiramo sve moguće kombinacije iz *key space-a*:

```bash
hydra -l gutesa_adriana -x 4:6:a 10.0.15.2 -V -t 4 ssh
```

Skidamo *dictionary,* koji je unaprijed sastavljen i sadrži potencijalne *password-e. Dictionary* ima oko **850 *password-a,* a potrebno je proći polovicu da bi se pronašao odgovarajući:

```bash
wget -r -nH -np --reject "index.html*" http://a507-server.local:8080/dictionary/g3/
```

Započinjemo napad:

```bash
hydra -l gutesa_adriana -P dictionary/g3/dictionary_online.txt 10.0.15.2 -V -t 4 ssh
```

![Snimka zaslona 2022-01-11 110710](https://user-images.githubusercontent.com/73557717/149668643-86de9be7-e822-48aa-89bb-dca426c68b83.png)

Otkrivenim *password-om* se sada možemo ulogirati u SSH.

![Snimka zaslona 2022-01-11 110756](https://user-images.githubusercontent.com/73557717/149668646-84cb4c88-007f-4826-9051-89ab4eda1f50.png)

---

## Offline Password Guessing

Pomoću alata *hashcat* želimo iz *hash* vrijednosti *passworda* dobiti izvorni *password*. *Password-i* su *hashirani* na način da je prvo definirana *hash* funckija koja se koristi, zatim je navedena sol te na kraju sama *hash* vrijednost *password-a.* Ukoliko bi koristili *brute force* napad sigurno bi otkrili *password* no za to bi nam trebalo 30ak dana te ćemo koristiti umjesto toga već sastavljeni *dictionary* za ovaj *offline* napad:

```bash
hashcat --force -m 1800 -a 0 hash.txt dictionary/g3/dictionary_offline.txt -- status --status-timer 10
```

U datoteci hash.txt se nalazi *hash* vrijednost iz koje želimo otkriti *password* te je pronađen *password* računa john_doe i pomoću njega se možemo ulogirati u račun:

```bash
ssh john_doe@10.0.15.2
```

---

## Zaključak

Oba napada, online i offline napad, trajali bi predugo da nismo imali unaprijed sastavljen *dictionary*. Upravo je to ono što će demotivirati napadača i povećati sigurnost naše lozinke. Kod *online* napada dobro je to što se direktno mogu isprobavati lozinke i dobiva se odgovor od servera je li prijava uspješno prošla, dok kod *offline* napada ne dobivamo povratne informacije dok se ne pokušamo ručno prijaviti u račun.
