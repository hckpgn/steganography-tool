import numpy as np
from PIL import Image
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import os
import sys
import time
from typing import Dict, Any
import colorama
from colorama import Fore, Style

# Initialize colorama for cross-platform colored output
colorama.init()


class SecureSteganography:
    def __init__(self, password: str):
        """Initialize with a password for encryption"""
        # Generate a secure key from the password
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'steganography_salt',
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        self.cipher_suite = Fernet(key)

    def _prepare_message(self, message: str) -> str:
        """Encrypt and prepare message for embedding"""
        padding = os.urandom(np.random.randint(10, 30))
        prepared_data = padding + b'|' + message.encode()
        encrypted_data = self.cipher_suite.encrypt(prepared_data)
        binary_data = ''.join(format(byte, '08b') for byte in encrypted_data)
        return binary_data

    def _validate_capacity(self, image: Image.Image, binary_data: str) -> None:
        """Check if image has enough capacity for the data"""
        max_bytes = (image.size[0] * image.size[1] * 3) // 8
        required_bytes = len(binary_data) // 8
        if required_bytes > max_bytes:
            raise ValueError(
                f"Data too large. Max capacity: {max_bytes} bytes\n"
                f"Required: {required_bytes} bytes"
            )

    def hide_message(self, image_path: str, message: str, output_path: str) -> None:
        """Hide an encrypted message in an image"""
        # Show progress animation
        self._show_progress("Preparing image", 0)

        img = Image.open(image_path)
        if img.mode != 'RGB':
            img = img.convert('RGB')
        img_array = np.array(img)

        self._show_progress("Encrypting message", 25)
        binary_data = self._prepare_message(message)
        self._validate_capacity(img, binary_data)

        length_binary = format(len(binary_data), '032b')
        binary_data = length_binary + binary_data

        self._show_progress("Embedding data", 50)
        flat_img = img_array.flatten()

        data_index = 0
        total_bits = len(binary_data)

        for i in range(total_bits):
            if data_index >= len(flat_img):
                break
            if int(binary_data[i]) != (flat_img[data_index] & 1):
                flat_img[data_index] = flat_img[data_index] ^ 1
            data_index += 1

            if i % (total_bits // 10) == 0:
                progress = 50 + (i / total_bits * 40)
                self._show_progress("Embedding data", progress)

        self._show_progress("Saving image", 90)
        modified_img = flat_img.reshape(img_array.shape)
        Image.fromarray(modified_img).save(output_path, 'PNG')

        self._show_progress("Complete", 100)
        time.sleep(0.5)
        print("\n" + Fore.GREEN + "Message hidden successfully!" + Style.RESET_ALL)

    def extract_message(self, image_path: str) -> str:
        """Extract and decrypt hidden message from image"""
        self._show_progress("Loading image", 0)

        img = Image.open(image_path)
        img_array = np.array(img)
        flat_img = img_array.flatten()

        self._show_progress("Extracting data", 30)
        length_binary = ''.join(str(pixel & 1) for pixel in flat_img[:32])
        message_length = int(length_binary, 2)

        self._show_progress("Processing data", 60)
        binary_message = ''.join(str(pixel & 1) for pixel in
                                 flat_img[32:32 + message_length])

        message_bytes = bytearray()
        for i in range(0, len(binary_message), 8):
            byte = binary_message[i:i + 8]
            message_bytes.append(int(byte, 2))

        self._show_progress("Decrypting", 90)
        try:
            decrypted_data = self.cipher_suite.decrypt(bytes(message_bytes))
            actual_message = decrypted_data[decrypted_data.index(b'|') + 1:]
            self._show_progress("Complete", 100)
            time.sleep(0.5)
            return actual_message.decode()
        except Exception as e:
            print(
                Fore.RED + "\nError: Failed to extract message. Invalid password or corrupted data." + Style.RESET_ALL)
            return ""

    def analyze_image_capacity(self, image_path: str) -> Dict[str, Any]:
        """Analyze how much data can be safely stored in the image"""
        img = Image.open(image_path)
        max_bytes = (img.size[0] * img.size[1] * 3) // 8
        return {
            'max_bytes': max_bytes,
            'max_chars': max_bytes // 4,
            'dimensions': img.size,
            'mode': img.mode
        }

    @staticmethod
    def _show_progress(message: str, percent: float) -> None:
        """Display a progress bar with message"""
        bar_width = 40
        filled = int(bar_width * percent / 100)
        bar = '█' * filled + '▒' * (bar_width - filled)
        print(f'\r{message}: [{bar}] {percent:0.1f}%', end='', flush=True)


class InteractiveSteganography:
    def __init__(self):
        self.stego = None

    def print_banner(self):
        banner = """
╔═══════════════════════════════════════════════════════════════╗
║                      Steganography Tool                       ║
║                          by hckpgn                            ║
╚═══════════════════════════════════════════════════════════════╝
        """
        print(Fore.CYAN + banner + Style.RESET_ALL)

    def print_menu(self):
        menu = """
1. Hide a message in an image
2. Extract a message from an image
3. Analyze image capacity
4. Change password
5. Exit

Choose an option (1-5): """
        print(Fore.YELLOW + menu + Style.RESET_ALL, end='')

    def get_password(self):
        while True:
            password = input(Fore.GREEN + "\nEnter password (min. 8 characters): " + Style.RESET_ALL)
            if len(password) >= 8:
                self.stego = SecureSteganography(password)
                break
            print(Fore.RED + "Password too short!" + Style.RESET_ALL)

    def hide_message_interface(self):
        try:
            input_image = input(Fore.GREEN + "\nEnter input image path: " + Style.RESET_ALL)
            if not os.path.exists(input_image):
                print(Fore.RED + "Error: Input image not found!" + Style.RESET_ALL)
                return

            # Analyze and show capacity
            capacity = self.stego.analyze_image_capacity(input_image)
            print(Fore.CYAN + f"\nImage capacity: {capacity['max_chars']} characters" + Style.RESET_ALL)

            message = input(Fore.GREEN + "Enter your secret message: " + Style.RESET_ALL)
            if not message:
                print(Fore.RED + "Error: Message cannot be empty!" + Style.RESET_ALL)
                return

            output_image = input(Fore.GREEN + "Enter output image path: " + Style.RESET_ALL)

            print("\nProcessing...")
            self.stego.hide_message(input_image, message, output_image)

        except Exception as e:
            print(Fore.RED + f"\nError: {str(e)}" + Style.RESET_ALL)

    def extract_message_interface(self):
        try:
            image_path = input(Fore.GREEN + "\nEnter image path: " + Style.RESET_ALL)
            if not os.path.exists(image_path):
                print(Fore.RED + "Error: Image not found!" + Style.RESET_ALL)
                return

            print("\nExtracting...")
            message = self.stego.extract_message(image_path)
            if message:
                print(Fore.GREEN + f"\nExtracted message: {message}" + Style.RESET_ALL)

        except Exception as e:
            print(Fore.RED + f"\nError: {str(e)}" + Style.RESET_ALL)

    def analyze_image_interface(self):
        try:
            image_path = input(Fore.GREEN + "\nEnter image path: " + Style.RESET_ALL)
            if not os.path.exists(image_path):
                print(Fore.RED + "Error: Image not found!" + Style.RESET_ALL)
                return

            capacity = self.stego.analyze_image_capacity(image_path)
            print(Fore.CYAN + "\nImage Analysis:" + Style.RESET_ALL)
            print(f"Dimensions: {capacity['dimensions'][0]}x{capacity['dimensions'][1]}")
            print(f"Mode: {capacity['mode']}")
            print(f"Maximum capacity: {capacity['max_bytes']} bytes")
            print(f"Maximum text length: {capacity['max_chars']} characters")

        except Exception as e:
            print(Fore.RED + f"\nError: {str(e)}" + Style.RESET_ALL)

    def run(self):
        self.print_banner()
        self.get_password()

        while True:
            try:
                self.print_menu()
                choice = input()

                if choice == '1':
                    self.hide_message_interface()
                elif choice == '2':
                    self.extract_message_interface()
                elif choice == '3':
                    self.analyze_image_interface()
                elif choice == '4':
                    self.get_password()
                elif choice == '5':
                    print(Fore.GREEN + "\nGoodbye!" + Style.RESET_ALL)
                    break
                else:
                    print(Fore.RED + "\nInvalid option!" + Style.RESET_ALL)

            except KeyboardInterrupt:
                print(Fore.YELLOW + "\n\nExiting..." + Style.RESET_ALL)
                break
            except Exception as e:
                print(Fore.RED + f"\nAn error occurred: {str(e)}" + Style.RESET_ALL)
                continue


if __name__ == "__main__":
    app = InteractiveSteganography()
    app.run()