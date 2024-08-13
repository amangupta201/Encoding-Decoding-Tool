# Encoding-Decoding-Tool
This tool is a comprehensive utility for encoding and decoding text using various encoding schemes. It can automatically identify and decode text based on its encoding type. Supported encodings include Base64, Base32, Base58, Base85, Base91, ROT13, URL Encoding, Morse Code, Hexadecimal, Binary, Octal, UUencode, and Quoted-Printable.

Features
Automatic Encoding Detection: Identifies the encoding type of the input text and decodes it accordingly.
Support for Multiple Encodings: Handles a variety of encoding schemes including Base64, Base32, Base58, Base85, Base91, ROT13, URL Encoding, Morse Code, Hexadecimal, Binary, Octal, UUencode, and Quoted-Printable.

Installation
To use this tool, you need to have Python installed. You can clone this repository and run the script directly.

1.Clone the repository:

git clone https://github.com/amangupta201/Encoding-Decoding-Tool.git
cd Encoding-Decoding-Tool

2.Install the required packages:
pip install base58 base91

3.Usage

Run the script and enter the encoded text when prompted. The script will automatically detect the encoding type and decode the text.
python encoding_decoding_tool.py

Example Input:

Enter the encoded text you want to decode: UHl0aG9uIDMuMTA=
Output:

Detected Encoding: Base64

Decoded Text: Python 3.10

