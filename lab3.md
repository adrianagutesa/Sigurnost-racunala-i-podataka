# Laboratorijske vježbe 3

# Message authentication and integrity

Zadatak vježbe je primjeniti teorijsko znanje o osnovnim kriptografskim mehanizmima za autentikaciju i zaštitu intengriteta poruka u praktičnim primjerima. Koristili smo simetrični kripto mehanizam: *message authentication code (MAC).*

---

### Izazov 1

Za ovaj izazov koristili smo Python biblioteku *cryptography.*

Prvo smo kreirali dvije datoteke: *message.txt* i *message.sig.* Iz datoteke *message.txt* pročitali smo tekst čiji integritet treba zaštititi. 

```python
if __name__ == "__main__":
    key = b"this is my key"

    with open("message.txt", "rb") as file:
        content = file.read()

    # mac = generate_MAC(key, content)

    # with open("message.sig", "wb") as file:
    #     file.write(mac)

    with open("message.sig", "rb") as file:
        signature = file.read()

    is_authentic = verify_MAC(key, signature, content)

    print(is_authentic)
```

Nakon toga smo generirali mac funkcijom koja za argumente prima neki proizvoljni ključ i poruku - tekst koji smo pročitali iz datoteke i spremili ga u datoteku *message.sig.* 

```python
def generate_MAC(key, message):
    if not isinstance(message, bytes):
        message = message.encode()

    h = hmac.HMAC(key, hashes.SHA256())
    h.update(message)
    signature = h.finalize()
    return signature
```

Pozivanjem funkcije **verify_MAC,** koja za argumente prima ključ, mac i poruku, lokalno generira novi mac te uspoređuje lokalni i prosljeđeni mac. Ukoliko dođe do podudaranja, funkcija vraća True: poruka autentična, a u suprotnom False: poruka nije autentična te je modificiran tekst poruke ili mac.

```python
def verify_MAC(key, signature, message):
    if not isinstance(message, bytes):
        message = message.encode()

    h = hmac.HMAC(key, hashes.SHA256())
    h.update(message)
    try:
        h.verify(signature)
    except InvalidSignature:
        return False
    else:
        return True
```

### Izazov 2

Za ovaj izazov također smo koristili Python biblioteku *cryptography.*

Nakon što smo s lokalnog servera preuzeli direktorij s našim imenom, u kojem se nalazilo 20 datoteka = 10 poruka + 10 MAC-ova, trebali smo učitati datoteke direktorija te provjeriti je li narušen integritet poruka. 

Ključ koji smo koristili:

```python
key = "gutesa_adriana".encode()
```

(kako datoteke nisu pohranjene u istom direktoriju gdje je i skripta, morali smo kreirati path do potrebnog direktorija)

```python
def verify_MAC(key, signature, message):
    if not isinstance(message, bytes):
        message = message.encode()

    h = hmac.HMAC(key, hashes.SHA256())
    h.update(message)
    try:
        h.verify(signature)
    except InvalidSignature:
        return False
    else:
        return True

if __name__ == "__main__":
	
    key = "gutesa_adriana".encode()
    path = os.path.join("challenges", "gutesa_adriana", "mac_challenge")
    
    for ctr in range(1, 11):
        msg_filename = f"order_{ctr}.txt"
	file_path_msg = os.path.join(path, msg_filename)
        sig_filename = f"order_{ctr}.sig"
	file_path_sig = os.path.join(path, sig_filename)

        with open(file_path_msg, "rb") as file:
            message = file.read()

        with open(file_path_sig, "rb") as file:
            signature = file.read()

        is_authentic = verify_MAC(key, signature, message)

        print(f'Message {message.decode():>45} {"OK" if is_authentic else "NOK":<6}')
```

Ovaj izazov je bio sličan izazovu 1 uz male modifikacije.
