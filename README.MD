# Cipher App

This is a simple cipher app that features:

- Caesar Cipher
- Base64 Encoding/Decoding

This is done using flask and python, with a simple html frontend and a Caesar Cipher python script.

### Usage

```bash
# Install the requirements
pip install -r requirements.txt

# Run the app
python app.py
```

### File Locations

All current and future cipher files will be located in the `Ciphers` folder.

Web application files are located in root directory.

## Caesar Cipher

The Caesar Cipher is a simple cipher that shifts the alphabet by a certain amount. For example, if the shift is 3, then
A becomes D, B becomes E, and so on. This is done by using the `ord()` and `chr()` functions in python.

What's different about this Caesar Cipher portion is the ability to include a One Time Pad (OTP) in the form of a `CSV`
or `TXT` file. This fortifies the cipher by adding a predefined shift to the characters.
The OTP looks like this:

```text
19 33 71 15 21 25 43 38 9 68 2 79 85 97 62 80 63 61 5 71 97 73 47 20 5 6 11 83 3 97 61 11 92 67 11 59 9 53 97 39 94 63 4 99 16 3 43 42 93 28 41 18 72 75 92 16 66 82 77 10 36 1 40 73 78 11 90 94 31 70 52 52 80 45 15 60 70 6 47 29 36 28 4 90 92 8 36 56 63 85 37 81 82 35 62 20 41 41 79 68 
```

Where each number is a shift value for each character in the message.

The OTP will be generated and saved into both a `CSV` and `TXT` file if `use_pad` is set to `True` but no `file_name`
or `file` is provided. This is done with `secrets` instead of `random` to ensure that the OTP is cryptographically
secure.
> Read more about `secrets` [here](https://docs.python.org/3/library/secrets.html#module-secrets)

### Usage of Caesar Cipher class

```python
# Import the class
from collections import deque

text = "Hello World, this is a test!"

# Pad Declaration using a list in a deque
pad = deque([19, 33, 71, 15, 21, 25, 43, 38, 9, 68, 2, 79, 85])

cipher = CaesarCipher(40, use_pad=False)
enc = cipher.encrypt(text)

decipher = CaesarCipher(40, use_pad=False)
dec = decipher.decrypt(enc)

cipher2 = CaesarCipher(40, use_pad=True, file_name='./pad.txt')
enc = cipher.encrypt(text)

decipher2 = CaesarCipher(40, use_pad=True, file_name='./pad.txt')
dec = decipher.decrypt(enc)
```

The Constructor allows for multiple parameters:

- `shift` - The shift value for the cipher (Default in the Web Application is 3, no default in the class)
- `pad` - `deque` object containing the OTP (Default is `None`)
- `file_name` - The name of the file containing the OTP (Default is `None`)
- `file` - The file containing the OTP (Default is `None`)
- `use_pad` - Whether to use the OTP (Default is `False`)

Above is the sample usage of the class. The object will have to be recreated for each message to be encrypted/decrypted
since
the OTP is a one time use.

## Base64 Encoding/Decoding

Base64 is a way to encode binary data into a string format. This is done by splitting the binary data into 6-bit chunks
and then converting each chunk into a character. This is done by using the `base64` module in python.

The base64 encoding/decoding is done using the `base64` module in the web application.

## Web Application

The web application is done using flask and python. The frontend is done using html and css.

This is a simple web application that allows the user to encrypt/decrypt messages using the Caesar Cipher and Base64
Encoding/Decoding.

Basic Functions:

- Fields are automatically updated as the user types in the message.
- The user can choose to use the OTP (via a file upload)
- Sliders can be used to change the shift value for the Caesar Cipher
- Both the Caesar Cipher and Base64 Encoding/Decoding can be used at the same time

### Launching the Web Application

To launch the web application, run the `app.py` file. This will launch the web application on `localhost:5000`.

```bash
python app.py
```

Ensure that the requirements in `requirements.txt` file is installed before running the application.