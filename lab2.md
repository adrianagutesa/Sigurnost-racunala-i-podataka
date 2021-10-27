# Laboratorijske vježbe 2

# Symmetric key cryptography - a crypto challenge

Zadatak vježbe je otkriti koji je naš enkriptirani dokument, pronaći ključ te pomoću njega dekriptirati enkriptirani dokument. Koristili smo Pyhton i biblioteku cryptography.

Prvi zadatak otkrivanja odgovarajućeg personaliziranog *plaintexta-a* (originali podaci koji se enkriptiraju) rješen je koristeći blok koda:

```python
from cryptography.hazmat.primitives import hashes

def hash(input):
    if not isinstance(input, bytes):
        input = input.encode()

    digest = hashes.Hash(hashes.SHA256())
    digest.update(input)
    hash = digest.finalize()

    return hash.hex()

filename = hash('gutesa_adriana') + ".encrypted"
```

Koristili smo Brute-force napad za otkrivanje ključa ograničene entropije - 22 bita kojom je bila enkriptirana naša datoteka čiji smo sadržaj pridružili varijabli *ciphertext* (enkriptirani podatak).

Budući da smo znali da je naš *ciphertext* slika (png), unutar while petlje smo svakom iteracijom pomoću trenutnog ključa pokušali dekripcijskim algoritmom dekriptirati *ciphertext* te bismo tu vrijednost pridružili varijabli *plaintext* i pozvali bismo funkciju test_png kojoj smo slali prva 32 bita *plaintext-a* gdje smo provjeravali odgovaraju li oni headeru-u datoteke png formata. Kada dođe do poklapanje, while petlja se prestaje vrtiti i dobivamo originalni sadržaj te saznajemo ključ.

```python
def test_png(header):
    if header.startswith(b"\211PNG\r\n\032\n"):
        return True

def brute_force():

    filename = "ecf1d3046988e913dce27ffbae7076efdf8b634754ce878a2c4eec15a36fd50c.encrypted"

    with open(filename, "rb") as file:
        ciphertext = file.read()
   
    ctr = 0
    while True:
        key_bytes = ctr.to_bytes(32, "big")
        key = base64.urlsafe_b64encode(key_bytes)
        if not (ctr + 1) % 1000:
            print(f"[*] Keys tested: {ctr + 1:,}", end = "\r")

        try:
            plaintext = Fernet(key).decrypt(ciphertext)
            header = plaintext[:32]

            if test_png(header):
                print(f"[+] KEY FOUND: {key}")
               
                with open(BINGO.png, "wb") as file:
                    file.write(plaintext)

                break
        except Exception:
            pass
        ctr += 1

if __name__ == "__main__":
    brute_force()
```