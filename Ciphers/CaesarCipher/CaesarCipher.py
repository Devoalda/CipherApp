import os
import secrets
from collections import deque
from typing import IO


class CaesarCipher:
    def __init__(self, shift: int, pad: deque = None, file_name: str = None, use_pad: bool = False,
                 file: IO[str] = None):
        """
        Constructor for CaesarCipher class
        :param shift: value to shift the alphabet by
        :type shift: int
        :param pad: pad to use for encryption/decryption
        :type pad: deque
        :param file_name: path to file containing pad
        :type file_name: str
        :param use_pad: True: use pad, False: generate pad
        :type use_pad: bool
        """

        self.shift = shift
        self.default_pad_length = 100
        self.file_type_dict = {
            '.txt': {
                'function': self.convert_txt_to_list,
                'default_file_name': 'pad.txt'
            },
            '.csv': {
                'function': self.convert_csv_to_list,
                'default_file_name': 'pad.csv'
            }
        }

        if use_pad is False:
            self.pad = deque([0] * self.default_pad_length)
        else:
            if file_name:
                file_name, file_extension = os.path.splitext(file_name)
                print(f'{file_name}, {file_extension}')
                if file_extension in self.file_type_dict:
                    self.file_type_dict[file_extension]["function"](file_name + file_extension)
            if file:
                self.read_file(file)
            else:
                self.pad = pad if pad else self.gen_pad(self.default_pad_length)

    def read_file(self, file: IO[str]) -> None:
        """
        Read file object into deque, space delimited or comma delimited
        :param file: file object to read
        :type file: IO[str]
        """
        # Try space delimited, then comma delimited
        try:
            self.pad = deque([int(num) for num in filter(str.isdigit, file.read().split(' '))])
            print(f'Space Pad: {self.pad}')
        except ValueError:
            self.pad = deque([int(num) for num in filter(str.isdigit, file.read().split(','))])
            print(f'comma Pad: {self.pad}')
        except Exception as e:
            print(f'Error reading file: {e}')

    def get_pad(self) -> int:
        """
        Get the next value from the pad
        :return: next value from the pad
        :rtype: int
        """

        try:
            pad_val = self.pad.popleft()
        except (IndexError, AttributeError):
            print(f'Error! Please pass the pad/pad file as an argument!')
            self.gen_pad()
            pad_val = self.pad.popleft()

        return pad_val

    def encrypt(self, plain_text: str) -> str:
        """
        Encrypt plain_text using the Caesar Cipher
        :param plain_text: text to encrypt
        :type plain_text: str
        :return: cipher text
        :rtype: str
        """

        result = ""
        for char in plain_text:
            if not char.isalpha():
                result += char
            else:
                pad_val = self.get_pad()
                result += chr((ord(char) + self.shift - 65 + pad_val) % 26 + 65) if char.isupper() else chr(
                    (ord(char) + self.shift - 97 + pad_val) % 26 + 97)
        print(f'Result: {result}')
        return result

    def decrypt(self, cipher_text: str) -> str:
        """
        Decrypt cipher_text using the Caesar Cipher
        :param cipher_text: text to decrypt
        :type cipher_text: str
        :return: plain text
        :rtype: str
        """

        result = ""
        for char in cipher_text:
            if not char.isalpha():
                result += char
            else:
                pad_val = self.get_pad()
                result += chr((ord(char) - self.shift - 65 - pad_val) % 26 + 65) if char.isupper() else chr(
                    (ord(char) - self.shift - 97 - pad_val) % 26 + 97)
        return result

    def gen_pad(self, length: int = None) -> None:
        """
        Generates a pad of random numbers, stores it in self.pad, and writes it to all default files (pad.txt, pad.csv)
        :param length: length of pad to generate, defaults to 100
        :type length: int
        :return: None
        """

        length = length if length else self.default_pad_length
        pad = deque()
        for i in range(length):
            pad.append(secrets.randbelow(length))

        self.pad = pad
        # write to all default files
        for key, value in self.file_type_dict.items():
            self.write_pad_to_file(value['default_file_name'])

    def write_pad_to_file(self, file_name: str = None) -> None:
        """
        Writes the pad to a file. If no file name is provided, the default file name is used.
        :param file_name: name of file to write pad to
        :type file_name: str
        :return: None
        """

        file_name = file_name if file_name else self.file_type_dict[os.path.splitext(file_name)[1]]['default_file_name']
        with open(file_name, 'w') as f:
            if file_name.endswith('.csv'):
                for i in self.pad:
                    f.write(f'{i},')
            else:
                for i in self.pad:
                    f.write(f'{i} ')

    def convert_txt_to_list(self, file_name: str = None) -> None:
        """
        Parses a text file containing a pad and stores it in object
        :param file_name: name of text file to read pad from
        :type file_name: str
        :return: None
        """

        file_name = file_name if file_name else self.file_type_dict[os.path.splitext(file_name)[1]]['default_file_name']
        try:
            with open(file_name, 'r') as f:
                pad = f.readline()
                pad = [int(i) for i in pad.split(' ') if i.strip()]
                self.pad = deque(pad)

        except FileNotFoundError:
            print(f'File {file_name} not found. Please check the file name and try again.')
            exit(1)

    def convert_csv_to_list(self, file_name: str = None) -> None:
        """
        Parses a csv file containing a pad and stores it in object
        :param file_name: name of csv file to read pad from
        :return: None
        """

        file_name = file_name if file_name else self.file_type_dict[os.path.splitext(file_name)[1]]['default_file_name']
        try:
            with open(file_name, 'r') as f:
                pad = f.readline()
                pad = [int(x) for x in pad.split(',') for x in x.split(' ') if x.strip()]
                self.pad = deque(pad)

        except FileNotFoundError:
            print(f'File {file_name} not found. Please check the file name and try again.')
            exit(1)


if __name__ == "__main__":
    text = "Hello World, this is a test!"

    cipher = CaesarCipher(40, use_pad=False)
    enc = cipher.encrypt(text)

    decipher = CaesarCipher(40, use_pad=False)
    dec = decipher.decrypt(enc)

    print(f'Original: {text}')
    print(f'Encrypted: {enc}')
    print(f'Decrypted: {dec}')

    assert text == dec, "Decrypted text does not match original text."
