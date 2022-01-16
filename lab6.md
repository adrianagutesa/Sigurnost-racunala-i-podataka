# Laboratorijske vježbe 6

# **Linux permissions and ACLs**

Zadatak ove vježbe bio je upoznati se s osnovnim postupcima upravljanja korisničkim računima u *Linux* Os-u. Osnovni cilj bio je analizirati kontrolu pristupa datotekama, programima i drugim resursima *Linux* sustava.

## A. Kreiranje novog korisničkog računa

U *Linux*-u svaka datoteka ili program (*binary executable file*) ima vlasnika (*user or owner*). Svakom korisniku pridjeljen je jedinstveni identifikator *User ID (UID)*. Svaki korisnik mora pripadati barem jednoj grupi (*group*), pri čemu više korisnika može dijeliti istu grupu. *Linux* grupe također imaju jedinstvene identifikatore *Group ID (GID)*.

- naredbom ***id*** provjeravamo *UserID* korisnika te kojim grupama pripada
- za kreiranje novog korisnika koristimo naredbu ***adduser***
    - jedino moguće ako pripadamo grupi: ***sudo*** - administratorska grupa
    
    ```bash
    sudo addsuer alice3
    sudo adduser bob3
    ```
    
    - kako bismo kreirali bob3 korisnika nakon što smo kreirali alice3, trebamo izvršiti naredbu ***exit*** kako bi se vratili u *shell* korisnika koj je član grupe ***sudo***
    - kreiranjem korisnika svaki od njih dobije svoj *UID* i *GID*
    
    ![Snimka zaslona 2022-01-11 112239](https://user-images.githubusercontent.com/73557717/149673361-5390183a-cb8d-40f8-9ac0-ed6e93852b18.png)
    

---

## **B**. **Standardna prava pristupa datotekama**

Logiramo se u sustav kao korisnik alice3, pozicioniramo se u direktorij /home/alice3 i kreiramo novi direktorij *SRP* te se pozicionoramo u njega. Kreiramo datoteku *security.txt* i u nju unesemo text *Hello World.*

- naredbom ***cd*** se pozicioniramo u željeni direktorij
- naredbom ***mkdir*** stvaramo novi direktorij
- naredbom **echo** “Hello World” > security. txt kreiramo datoteku s tekstom
- naredbom **cat** security.txt ispisujemo sadržaj datoteke
- naredbama ***ls -l*** ili ***getfacl*** izlistavamo informacije o direktoriju i datotekama

```bash
alice3@DESKTOP-7Q0BASR:~/SRP$ getfacl security.txt
file: security.txt
owner: alice3
group: alice3
user::rw-
group::rw-
other::r--
```

Vidimo da je korisnik alice3 vlasnik datoteke i da pripada grupi alice3. Vlasnik ima pravo čitanja i pisanja u datoteku kao i članovi grupe alice3 dok ostali korisnici imaju samo pravo čitanja.

```bash
alice3@DESKTOP-7Q0BASR:~/SRP$ getfacl .
file: .
owner: alice3
group: alice
user::rwx
group::rwx
other::r-x
```

Za direktorij *SRP* vidmo slične ovlasti, a jedina razlika je u pravu *x* koji predstavlja naredbu *execute* što znači da svi mogu pristupiti direktoriju.

Oduzimanje i davanje prava nad datotekom *security.txt*:

- za oduzimanje prava pristupa vlasniku (alice3) datoteke koristimo nardbu ***chmod***
    
    ```bash
    alice3@DESKTOP-7Q0BASR:~/SRP$ chmod u-r security.txt
    alice3@DESKTOP-7Q0BASR:~/SRP$ getfacl security.txt
    file: security.txt
    owner: alice3
    group: alice3
    user::-w-
    group::rw-
    other::r--
    ```
    
    - ukoliko sad alice3 pokuša pročitati datoteku, pristup će joj biti odbijen
        
        ```bash
        alice3@DESKTOP-7Q0BASR:~/SRP$ cat security.txt
        cat: security.txt: Permission denied
        ```
        
- za vraćanje prava pristupa vlasniku (alice3) datoteke također koristimo nardbu ***chmod***
    
    ```bash
    alice3@DESKTOP-7Q0BASR:~/SRP$ chmod u+r security.txt
    alice3@DESKTOP-7Q0BASR:~/SRP$ cat security.txt
    Hello World
    ```
    

Ako se logiramo kao korisnik bob3 i pokušamo čitati datoteku, imat ćemo to pravo no ukoliko alice3 oduzme pravo čitanja ostalim korisnicima tada ni bob3 neće više moći čitati datoteku jer nije vlasnik niti pripada grupi alice3.

Ukoliko bob3 pokuša pristupiti datoteci /etc/shadow, koja pohranjuje *hash* ključeve, neće imati pristup zato što ne pripada grupi *shadow* i nije *root* korisnik, a ostali nad tom datotekom nemaju nikakva prava.

```bash
bob3@DESKTOP-7Q0BASR:~$ getfacl /etc/shadow
getfacl: Removing leading '/' from absolute path names
file: etc/shadow
owner: root
group: shadow
user::rw-
group::r--
other::---
```

- primjeri primjene naredbe ***chmod***
    
    ```bash
    # Remove (u)ser (r)ead permission
    chmod u-r security.txt
    
    # Add (u)ser (r)ead permission
    chmod u+r security.txt
    
    # Remove both (u)ser and (g)roup (w)rite permission
    chmod ug-w security.txt
    
    # Add (u)ser (w)rite and remove (g)roup (r)ead permission
    chmod u+w,g-r security.txt
    
    # Add (u)ser (r)read, (w)rite permissions and remove e(x)ecute permpission
    chmod u=rw security.txt
    ```
    

---

## C. **Kontrola pristupa korištenjem *Access Control Lists (ACL)***

Kao admin možemo dati korisniku bob3 pravo na čitanje datoteke *security.txt*. Na taj način, eksplicitno dodajemo korisnika bob3 u ACL datoteke *security.txt* te on sada može čitati datoteku.

```bash
student@DESKTOP-7Q0BASR:/mnt/c/Users/A507$ sudo setfacl -m
u:bob3:r /home/alice3/SRP/security.txt
student@DESKTOP-7Q0BASR:/mnt/c/Users/A507$ getfacl /home/alice3/SRP/security.txt
getfacl: Removing leading '/' from absolute path names
file: home/alice3/SRP/security.txt
owner: alice3
group: alice3
user::rw-
user:bob3:r--
group::rw-
mask::rw-
other::---
```

- uklanjanje zapisa iz ACL-a
    
    ```bash
    # Removing one entry from ACL
    setfacl -x u:bob3 security.txt
    
    # Removing the complete ACL
    setfacl -b security.txt
    ```
    

Zaključujemo da je lakši način za davanje pristupa pojedinim korisnicima da napravimo grupe s potrebnim pravima pristupa, te u njih naknadno dodajemo korisnike kojima dopuštamo određena prava kako ne bi morali za svakog korisnika eksplicitno dodavati i uklanjati prava pristupa datoteci kada za to dođe potreba.

---

## D. **Linux procesi i kontrola pristupa**

Otvaranjem *Python* skripte *lab6g3.py* upisujemo kod:

```python
import os

print('Real (R), effective (E) and saved (S) UIDs:')
print(os.getresuid())

with open('/home/alice3/SRP/security.txt', 'r') as f:
print(f.read())
```

Program ispisuje stvarnog, efektivnog i “saved” vlasnika pokrenutog procesa te pokušava otvoriti datoteku *security.txt.*

- skriptu otvaramo kao bob3

```bash
bob3@DESKTOP-7Q0BASR:~$ python /mnt/c/Users/A507/lab6g3.py
Real (R), effective (E) and saved (S) UIDs:
(1006, 1006, 1006)
Traceback (most recent call last):
File "/mnt/c/Users/A507/lab6g3.py", line 6, in <module>
with open('/home/alice3/SRP/security.txt', 'r') as f:
IOError: [Errno 13] Permission denied: '/home/alice3/SRP/security.txt'
```

- skriptu otvaramo kao alice3

```bash
alice3@DESKTOP-7Q0BASR:~$ python /mnt/c/Users/A507/lab6g3.py
Real (R), effective (E) and saved (S) UIDs:
(1005, 1005, 1005)
Hello World
```

Korisnik bob3 nije uspio pročitati datoteku *security.txt* i dobio je odgovor *Permission denied* dok je alice3, kako vlasnica, uspjela pročitati datoteku.

Ukoliko korisnika bob3 dodamo u ACL datoteku *security.txt* imat će pravo pristupa:

```bash
student@DESKTOP-7Q0BASR:/mnt/c/Users/A507$ sudo setfacl -m u:bob3:r /home/alice3/SRP/security.txt
```

Ponovnim pokretanjem skripte dobijemo rezultat:

```bash
bob3@DESKTOP-7Q0BASR:~$ python /mnt/c/Users/A507/lab6g3.py
Real (R), effective (E) and saved (S) UIDs:
(1006, 1006, 1006)
Hello World
```
