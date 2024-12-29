import tkinter as tk
from tkinter import ttk, messagebox
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

reverse_morse_dict = {v: k for k, v in MORSE_CODE_DICT.items()}

# Encoding functions
def encode_uu(text):
    in_file = io.BytesIO(text.encode())
    out_file = io.BytesIO()
    uu.encode(in_file, out_file, name='data', backtick=True)
    out_file.seek(0)
    return out_file.getvalue().decode()

def decode_uu(encoded_text):
    in_file = io.BytesIO(encoded_text.encode())
    out_file = io.BytesIO()
    uu.decode(in_file, out_file)
    out_file.seek(0)
    return out_file.getvalue().decode()

def encode_base64(text):
    return base64.b64encode(text.encode()).decode()

def decode_base64(encoded_text):
    return base64.b64decode(encoded_text).decode()

def encode_base58(text):
    return base58.b58encode(text.encode()).decode()

def decode_base58(encoded_text):
    return base58.b58decode(encoded_text).decode()

def encode_base91(text):
    return base91.encode(text.encode())

def decode_base91(encoded_text):
    return base91.decode(encoded_text).decode()

def encode_rot13(text):
    return codecs.encode(text, 'rot_13')

def decode_rot13(encoded_text):
    return codecs.decode(encoded_text, 'rot_13')

def encode_url(text):
    return urllib.parse.quote(text)

def decode_url(encoded_text):
    return urllib.parse.unquote(encoded_text)

def encode_morse(text):
    return ' '.join(MORSE_CODE_DICT.get(char.upper(), '?') for char in text)

def decode_morse(encoded_text):
    return ''.join(reverse_morse_dict.get(code, '?') for code in encoded_text.split())

def perform_action(action, text, encoding_type):
    try:
        encodings = {
            'Base64': (encode_base64, decode_base64),
            'Base58': (encode_base58, decode_base58),
            'Base91': (encode_base91, decode_base91),
            'ROT13': (encode_rot13, decode_rot13),
            'URL': (encode_url, decode_url),
            'Morse Code': (encode_morse, decode_morse),
            'UUencode': (encode_uu, decode_uu)
        }

        encode_func, decode_func = encodings.get(encoding_type)
        return encode_func(text) if action == 'Encode' else decode_func(text)
    except Exception as e:
        return f"Error: {e}"

# Tkinter GUI
def main():
    def process_action():
        action = action_var.get()
        encoding_type = encoding_var.get()
        input_text = input_text_box.get("1.0", tk.END).strip()

        if not input_text:
            messagebox.showerror("Error", "Input text cannot be empty.")
            return

        result = perform_action(action, input_text, encoding_type)
        output_text_box.delete("1.0", tk.END)
        output_text_box.insert(tk.END, result)

    def clear_fields():
        input_text_box.delete("1.0", tk.END)
        output_text_box.delete("1.0", tk.END)

    root = tk.Tk()
    root.title("Encoding & Decoding Tool")

    # Input Text
    tk.Label(root, text="Input Text:").grid(row=0, column=0, sticky="w", padx=10, pady=5)
    input_text_box = tk.Text(root, height=5, width=60)
    input_text_box.grid(row=1, column=0, columnspan=2, padx=10, pady=5)

    # Encoding Type
    tk.Label(root, text="Encoding Type:").grid(row=2, column=0, sticky="w", padx=10, pady=5)
    encoding_var = tk.StringVar(value="Base64")
    encoding_menu = ttk.Combobox(root, textvariable=encoding_var, state="readonly",
                                 values=['Base64', 'Base58', 'Base91', 'ROT13', 'URL', 'Morse Code', 'UUencode'])
    encoding_menu.grid(row=2, column=1, padx=10, pady=5)

    # Action
    tk.Label(root, text="Action:").grid(row=3, column=0, sticky="w", padx=10, pady=5)
    action_var = tk.StringVar(value="Encode")
    action_menu = ttk.Combobox(root, textvariable=action_var, state="readonly", values=['Encode', 'Decode'])
    action_menu.grid(row=3, column=1, padx=10, pady=5)

    # Output Text
    tk.Label(root, text="Output Text:").grid(row=4, column=0, sticky="w", padx=10, pady=5)
    output_text_box = tk.Text(root, height=5, width=60)
    output_text_box.grid(row=5, column=0, columnspan=2, padx=10, pady=5)

    # Buttons
    process_button = tk.Button(root, text="Process", command=process_action)
    process_button.grid(row=6, column=0, padx=10, pady=10)

    clear_button = tk.Button(root, text="Clear", command=clear_fields)
    clear_button.grid(row=6, column=1, padx=10, pady=10)

    root.mainloop()

if __name__ == "__main__":
    main()
