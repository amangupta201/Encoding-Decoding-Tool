import base64
import base58
import base91
import urllib.parse
import codecs
import uu
import quopri
import io

# Morse Code Dictionary
MORSE_CODE_DICT = {
    'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.', 'F': '..-.', 'G': '--.', 'H': '....', 'I': '..',
    'J': '.---', 'K': '-.-', 'L': '.-..', 'M': '--', 'N': '-.', 'O': '---', 'P': '.--.', 'Q': '--.-', 'R': '.-.',
    'S': '...', 'T': '-', 'U': '..-', 'V': '...-', 'W': '.--', 'X': '-..-', 'Y': '-.--', 'Z': '--..', '1': '.----',
    '2': '..---', '3': '...--', '4': '....-', '5': '.....', '6': '-....', '7': '--...', '8': '---..', '9': '----.',
    '0': '-----', ',': '--..--', '.': '.-.-.-', '?': '..--..', '/': '-..-.', '-': '-....-', '(': '-.--.',
    ')': '-.--.-', '!': '-.-.--', '&': '.-...', ':': '---...', ';': '-.-.-.', '=': '-...-', '+': '.-.-.',
    '_': '..--.-', '"': '.-..-.', '$': '...-..-', '@': '.--.-.', "'": '.----.', ' ': '|'
}


# Encoding functions
def encode_uu(text):
    """Encodes text using UUencoding and returns as a string."""
    in_file = io.BytesIO(text.encode())
    out_file = io.BytesIO()
    uu.encode(in_file, out_file, name='data', backtick=True)
    out_file.seek(0)
    return out_file.getvalue().decode()


def decode_uu(encoded_text):
    """Decodes UUencoded text from a string and returns as a string."""
    in_file = io.BytesIO(encoded_text.encode())
    out_file = io.BytesIO()
    uu.decode(in_file, out_file)
    out_file.seek(0)
    return out_file.getvalue().decode()


def encode_base64(text):
    return base64.b64encode(text.encode()).decode()


def decode_base64(encoded_text):
    try:
        return base64.b64decode(encoded_text.strip()).decode('utf-8')
    except Exception as e:
        return f"Decoding Error: {e}"


def encode_base32(text):
    return base64.b32encode(text.encode()).decode()


def decode_base32(encoded_text):
    try:
        return base64.b32decode(encoded_text.strip()).decode('utf-8')
    except Exception as e:
        return f"Decoding Error: {e}"


def encode_base58(text):
    return base58.b58encode(text.encode()).decode()


def decode_base58(encoded_text):
    try:
        return base58.b58decode(encoded_text.strip()).decode('utf-8')
    except Exception as e:
        return f"Decoding Error: {e}"


def encode_base85(text):
    return base64.b85encode(text.encode()).decode()


def decode_base85(encoded_text):
    try:
        return base64.b85decode(encoded_text.strip()).decode('utf-8')
    except Exception as e:
        return f"Decoding Error: {e}"


def encode_base91(text):
    return base91.encode(text.encode())


def decode_base91(encoded_text):
    try:
        return base91.decode(encoded_text.strip()).decode('utf-8')
    except Exception as e:
        return f"Decoding Error: {e}"


def encode_rot13(text):
    return codecs.encode(text, 'rot_13')


def decode_rot13(encoded_text):
    return codecs.decode(encoded_text.strip(), 'rot_13')


def encode_url(text):
    return urllib.parse.quote(text)


def decode_url(encoded_text):
    return urllib.parse.unquote(encoded_text)


def encode_morse(text):
    return ' '.join(MORSE_CODE_DICT.get(char.upper(), '?') for char in text)


def decode_morse(encoded_text):
    reverse_morse_dict = {v: k for k, v in MORSE_CODE_DICT.items()}
    return ''.join(reverse_morse_dict.get(code, '?') for code in encoded_text.split())


def encode_hex(text):
    return text.encode().hex()


def decode_hex(encoded_text):
    try:
        return bytes.fromhex(encoded_text.strip()).decode('utf-8')
    except Exception as e:
        return f"Decoding Error: {e}"


def encode_binary(text):
    return ' '.join(format(ord(char), '08b') for char in text)


def decode_binary(encoded_text):
    try:
        binary_values = encoded_text.split()
        return ''.join(chr(int(bv, 2)) for bv in binary_values)
    except Exception as e:
        return f"Decoding Error: {e}"


def encode_octal(text):
    return ' '.join(format(ord(char), 'o') for char in text)


def decode_octal(encoded_text):
    try:
        octal_values = encoded_text.split()
        return ''.join(chr(int(ov, 8)) for ov in octal_values)
    except Exception as e:
        return f"Decoding Error: {e}"


def encode_quopri(text):
    return quopri.encodestring(text.encode()).decode()


def decode_quopri(encoded_text):
    try:
        return quopri.decodestring(encoded_text.encode()).decode('utf-8')
    except Exception as e:
        return f"Decoding Error: {e}"


# Function to decode the encoded string
def identify_and_decode(encoded_text):
    encodings = {
        'Base64': decode_base64,
        'Base32': decode_base32,
        'Base58': decode_base58,
        'Base85': decode_base85,
        'Base91': decode_base91,
        'ROT13': decode_rot13,
        'URL': decode_url,
        'Morse Code': decode_morse,
        'Hexadecimal': decode_hex,
        'Binary': decode_binary,
        'Octal': decode_octal,
        'UUencode': decode_uu,
        'Quoted-Printable': decode_quopri
    }

    results = {}
    for name, decode_func in encodings.items():
        try:
            decoded = decode_func(encoded_text)
            results[name] = decoded
        except Exception as e:
            results[name] = f"Failed to decode: {str(e)}"

    return results


# Main program with user input
def main():
    mode = input("Enter '1' to encode/decode a string or '2' to test decoding an encoded string: ")

    if mode == '1':
        text = input("Enter the text you want to encode/decode: ")

        # Encoding and Decoding examples
        encodings = [
            ('Base64', encode_base64, decode_base64),
            ('Base32', encode_base32, decode_base32),
            ('Base58', encode_base58, decode_base58),
            ('Base85', encode_base85, decode_base85),
            ('Base91', encode_base91, decode_base91),
            ('ROT13', encode_rot13, decode_rot13),
            ('URL', encode_url, decode_url),
            ('Morse Code', encode_morse, decode_morse),
            ('Hexadecimal', encode_hex, decode_hex),
            ('Binary', encode_binary, decode_binary),
            ('Octal', encode_octal, decode_octal),
            ('UUencode', encode_uu, decode_uu),
            ('Quoted-Printable', encode_quopri, decode_quopri)
        ]

        for name, encode_func, decode_func in encodings:
            try:
                encoded = encode_func(text)
                decoded = decode_func(encoded)
                print(f"{name} Encoded: {encoded}")
                print(f"{name} Decoded: {decoded}")
                print()
            except Exception as e:
                print(f"Error with {name}: {e}")
                print()

    elif mode == '2':
        encoded_text = input("Enter the encoded string to decode: ")
        results = identify_and_decode(encoded_text)
        for name, result in results.items():
            print(f"Decoded using {name}: {result}")
            print()

    else:
        print("Invalid option selected.")


if __name__ == "__main__":
    main()
