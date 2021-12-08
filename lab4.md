# Laboratorijske vježbe 4

# **Digital signatures using public-key cryptography**

U ovom izazovu trebamo odrediti autentičnu sliku (između dvije ponuđene) koju je profesor potpisao svojim privatnim ključem. Slike s odgovarajućim potpisom i javni ključ smo skinuli sa servera.

---

Prvo smo ispisali i deserijalizirali javni ključ koji je pohranjen u datoteci *public.pem.*

```python
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

def load_public_key():
    with open("public.pem", "rb") as f:
        PUBLIC_KEY = serialization.load_pem_public_key(
            f.read(),
            backend=default_backend()
        )
    return PUBLIC_KEY
```

Nakon toga smo provjerili autentičnost slika potpisanih privatnim ključem:

```python
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature

def load_public_key():
    with open("public.pem", "rb") as f:
        PUBLIC_KEY = serialization.load_pem_public_key(
            f.read(),
            backend=default_backend()
        )
    return PUBLIC_KEY

def verify_signature_rsa(signature, message):
    PUBLIC_KEY = load_public_key()
    try:
        PUBLIC_KEY.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
    except InvalidSignature:
        return False
    else:
        return True

# ====================

with open("image_1.sig", "rb") as file:
    signature = file.read()

with open("image_1.png", "rb") as file:
    image = file.read()

is_authentic = verify_signature_rsa(signature, image)
print(is_authentic)
```

Funkciji *verify_signature_rsa* šaljemo potpis i sliku jer će se sa slikom izračunati njezina hash vrijednost, a potpis ćemo dekodirati s javnim ključem i usporediti dobivene vrijednosti. Za prvu sliku smo dobili ispis *False* što znači da ne možemo utvrditi autentičnost slike dok smo za drugu dobili *True* što znači da je slika autentična.


![Snimka zaslona 2021-12-08 220831](https://user-images.githubusercontent.com/73557717/145285130-944513d3-9e35-4d62-999b-d9271f9feac7.png)


# **Password-hashing (iterative hashing, salt, memory-hard functions)**

U ovom izazovu smo se upoznali a osnovnim konceptima relevantnim za sigurnu pohranu lozinki. Usporedili smo klasične (*brze*) kriptografske *hash* funkcije sa specijaliziranim (*sporim* i *memorijski zahtjevnim*) kriptografskim funkcijama za sigurnu pohranu zaporki i izvođenje enkripcijskih ključeva (*key derivation function (KDF)*).

---

Pomoću kod kojim se provjeravaju brzine kriptografskih hash funckija i AES-a zaključili smo da se hash funkcije izvršavaju dosta brzo, a cilj nam je povećati vrijeme hashiranja kako bi demotivirali napadača da stvori *dictionary* u kojem se nalaze parovi lozinki i hash vrijednosti. Dodali smo u kod ispis vremena za *linux_hash* za 5000 i 10^6 iteracija.

```python
from os import urandom
from prettytable import PrettyTable
from timeit import default_timer as time
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from passlib.hash import sha512_crypt, pbkdf2_sha256, argon2

def time_it(function):
    def wrapper(*args, **kwargs):
        start_time = time()
        result = function(*args, **kwargs)
        end_time = time()
        measure = kwargs.get("measure")
        if measure:
            execution_time = end_time - start_time
            return result, execution_time
        return result
    return wrapper

@time_it
def aes(**kwargs):
    key = bytes([
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    ])

    plaintext = bytes([
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    ])

    encryptor = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    encryptor.update(plaintext)
    encryptor.finalize()

@time_it
def md5(input, **kwargs):
    digest = hashes.Hash(hashes.MD5(), backend=default_backend())
    digest.update(input)
    hash = digest.finalize()
    return hash.hex()

@time_it
def sha256(input, **kwargs):
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(input)
    hash = digest.finalize()
    return hash.hex()

@time_it
def sha512(input, **kwargs):
    digest = hashes.Hash(hashes.SHA512(), backend=default_backend())
    digest.update(input)
    hash = digest.finalize()
    return hash.hex()

@time_it
def pbkdf2(input, **kwargs):
    # For more precise measurements we use a fixed salt
    salt = b"12QIp/Kd"
    rounds = kwargs.get("rounds", 10000)
    return pbkdf2_sha256.hash(input, salt=salt, rounds=rounds)

@time_it
def argon2_hash(input, **kwargs):
    # For more precise measurements we use a fixed salt
    salt = b"0"*22
    rounds = kwargs.get("rounds", 12)              # time_cost
    memory_cost = kwargs.get("memory_cost", 2**10) # kibibytes
    parallelism = kwargs.get("rounds", 1)
    return argon2.using(
        salt=salt,
        rounds=rounds,
        memory_cost=memory_cost,
        parallelism=parallelism
    ).hash(input)

@time_it
def linux_hash_6(input, **kwargs):
    # For more precise measurements we use a fixed salt
    salt = "12QIp/Kd"
    return sha512_crypt.hash(input, salt=salt, rounds=5000)

@time_it
def linux_hash(input, **kwargs):
    # For more precise measurements we use a fixed salt
    salt = kwargs.get("salt")
    rounds = kwargs.get("rounds", 5000)
    if salt:
        return sha512_crypt.hash(input, salt=salt, rounds=rounds)
    return sha512_crypt.hash(input, rounds=rounds)

@time_it
def scrypt_hash(input, **kwargs):
    salt = kwargs.get("salt", urandom(16))
    length = kwargs.get("length", 32)
    n = kwargs.get("n", 2**14)
    r = kwargs.get("r", 8)
    p = kwargs.get("p", 1)
    kdf = Scrypt(
        salt=salt,
        length=length,
        n=n,
        r=r,
        p=p
    )
    hash = kdf.derive(input)
    return {
        "hash": hash,
        "salt": salt
    }

if __name__ == "__main__":
    ITERATIONS = 100
    password = b"super secret password"

    MEMORY_HARD_TESTS = []
    LOW_MEMORY_TESTS = []

    TESTS = [
        {
            "name": "AES",
            "service": lambda: aes(measure=True)
        },
        {
            "name": "HASH_MD5",
            "service": lambda: sha512(password, measure=True)
        },
        {
            "name": "HASH_SHA256",
            "service": lambda: sha512(password, measure=True)
        },
        {
            "name": "Linux CRYPT 5k",
            "service": lambda: linux_hash(password, measure=True)
        },
        {
            "name": "Linux CRYPT 1M",
            "service": lambda: linux_hash(password, rounds=10**6, measure=True)
        }        

    ]

    table = PrettyTable()
    column_1 = "Function"
    column_2 = f"Avg. Time ({ITERATIONS} runs)"
    table.field_names = [column_1, column_2]
    table.align[column_1] = "l"
    table.align[column_2] = "c"
    table.sortby = column_2

    for test in TESTS:
        name = test.get("name")
        service = test.get("service")

        total_time = 0
        for iteration in range(0, ITERATIONS):
            print(f"Testing {name:>6} {iteration}/{ITERATIONS}", end="\r")
            _, execution_time = service()
            total_time += execution_time
        average_time = round(total_time/ITERATIONS, 6)
        table.add_row([name, average_time])
        print(f"{table}\n\n")
```

U ispisu vidimo vrijeme potrebno za izvođenje pojedinih funkcija te povećavanjem broja iteracija značajno usporavamo vrijeme hashiranja i tako demotiviramo napadača da u kratkom vremenu napravi *dictionary.*

Ukoliko štitimo jako bitne podatke kojima ne pristupamo tako često možemo koristiti veliki broj (milijun) iteracija hashiranja iako traje predugo, ali će vjerojatnost napada biti manja  no ukoliko nemamo tako bitne podatke, a često se hashiraju možemo koristiti kriptografske hash funkcije kako bi ubrzali sustav, ali postoji rizik od napada.

![Snimka zaslona 2021-12-08 220923](https://user-images.githubusercontent.com/73557717/145285202-12208d0b-7c80-41f1-85cd-8848b880e8ce.png)
