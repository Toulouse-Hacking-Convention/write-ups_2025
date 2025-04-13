## Writeup

### Flag 1: Extracting `creds.zip`

1. Gather Clues using **Volatility** plugins.
2. Find a suspicious file with:
   ```sh
   $ python3 vol.py  -f dump windows.filescan | grep creds.zip
   0x8007d2a77370.0\Users\Dimitri Ieba\Desktop\creds.zip
   0x8007d31207f0  \Users\Dimitri Ieba\Desktop\creds.zip
   ```
3. Extract the file:
   ```sh
   python3 vol.py -f dump.raw windows.dumpfiles --virtaddr 0x8007d2a77370
   ```
4. Use **zip2john** to extract the hash:
   ```sh
   zip2john file.0x8007d2a77370.0x8007cd9aa170.DataSectionObject.creds.zip.dat > hash
   ```
5. Crack the password:
   ```sh
   john --wordlist=/usr/share/wordlists/rockyou.txt hash
   ```
6. Unzip the file using the password:
   ```sh
   unzip -P hihi23 file.0x8007d2a77370.0x8007cd9aa170.DataSectionObject.creds.zip.dat
   ```

---

### Flag 2: Decrypting & Exploring the Disk

1. Decrypt and mount the disk:
   ```sh
   sudo mkdir -p /mnt/vhd /mnt/dislocker
   sudo losetup -fP disk_encrypted.vhd
   sudo dislocker -V /dev/loop0p1 -u1_l1k3_c00ff33 -- /mnt/dislocker
   sudo mount -o loop /mnt/dislocker/dislocker-file /mnt/vhd
   ```
2. Find the hidden picture:
   ```sh
   ls /mnt/vhd/Users/Dimitri\ Ieba/Pictures/logo_gang.jpg
   ```
3. Have a look at the picture metadata:
   ```sh
   exiftool logo_gang.jpg
   ```
4. Extract hidden files using **steghide**:
   ```sh
   steghide extract -sf logo_gang.jpg
   ```
   - Enter the guessed password: **`THC`**.
   - Or brute force the password using `stegseek logo_gang.jpg pswds` 

---

### Flag 3: Reverse Engineering `check_creds.exe`

1. Analyze the executable in **Ghidra**.
2. Understand its logic:
   - It requires a password.
   - The password is hashed into an **NTLM hash**.
   - The hash is **XORed** with some data.
3. Find the NTLM hash in the memory dump:
   ```sh
   python3 vol.py -f dump.raw windows.hashdump
   ```
   - Extract the correct hash and recover the flag.

