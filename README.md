# Steganography Tool

This is a secure steganography tool that allows you to hide and extract messages in images using encryption.

## Disclaimer

This tool is for educational purposes only. Always respect copyright and privacy laws when using steganography.

## Features

- Hide encrypted messages in images
- Extract and decrypt hidden messages from images
- Analyze image capacity for data hiding
- Password-based encryption for added security
- Interactive command-line interface

## Requirements

- Python 3.6+
- Required Python packages:
  - [NumPy](https://numpy.org/)
  - [Pillow](https://python-pillow.org/)
  - [cryptography](https://cryptography.io/)
  - [colorama](https://pypi.org/project/colorama/)

## Installation

1. Clone this repository or download the source code.
2. Install the required packages:

```python
pip install -r requirements.txt
```

## Usage

Run the script:

```
python3 steganography.py
```

Follow the on-screen prompts to:

1. Set a password
2. Hide a message in an image
3. Extract a message from an image
4. Analyze image capacity
5. Change password

## Security

This tool uses PBKDF2 for key derivation and Fernet for symmetric encryption, providing a high level of security for your hidden messages.

## Note

- Always keep your password safe. If you lose the password, you won't be able to recover hidden messages.
- For enhanced security, it is recommended to change the salt value in the code. Look for the line `salt=b'steganography_salt'` in the `SecureSteganography` class and replace it with your own unique salt.

## License

This project is open-source and available under the MIT License.
