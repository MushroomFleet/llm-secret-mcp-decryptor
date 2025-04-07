# LLM-Secrets Decryption Tool

A standalone tool for decrypting files created by the LLM-Secrets system. This tool enables researchers to access and analyze the private thoughts that were encrypted during the LLM interaction process.

## Features

- Compatible with the encryption method used in the LLM-Secrets project
- Supports both interactive and command-line modes
- Provides options for displaying or saving decrypted content
- Uses the same AES-256 encryption algorithm for seamless decryption
- Configuration management via settings.json

## Setup

### Prerequisites

- Python 3.8 or higher
- cryptography package

### Installation

1. Install the required packages:
```
pip install cryptography
```

2. The tool is ready to use with the included settings.json file.

## Usage

The decryption tool can be used in several ways:

### Using Saved Configuration

The easiest way to decrypt files is to use the configuration in settings.json, which already contains the encryption key:

```
python decrypt.py --config --file ../private/private_thought_20250406170040.enc
```

### Interactive Mode

Run the tool without arguments for interactive mode:

```
python decrypt.py
```

The tool will:
1. Prompt for the encryption key if not specified
2. Show available encrypted files in the default folder
3. Let you choose which file to decrypt
4. Display the decrypted content

### Command-Line Options

```
usage: decrypt.py [-h] [-c] [-k KEY] [-f FILE] [-o OUTPUT] [-d OUTPUT_DIR] [-q]

LLM-Secrets Decryption Tool

optional arguments:
  -h, --help            show this help message and exit
  -c, --config          Use settings from config file
  -k, --key KEY         Base64 encoded encryption key
  -f, --file FILE       Path to encrypted file
  -o, --output OUTPUT   Path to save decrypted output
  -d, --output-dir OUTPUT_DIR
                        Directory to save decrypted output
  -q, --quiet           Suppress console output
```

## Examples

### Decrypt and Display Content

```
python decrypt.py --config --file ../private/private_thought_20250406170040.enc
```

### Decrypt and Save to File

```
python decrypt.py --config --file ../private/private_thought_20250406170040.enc --output ./my_decrypted_file.txt
```

### Decrypt and Save to Default Output Directory

```
python decrypt.py --config --file ../private/private_thought_20250406170040.enc --output-dir outputs
```

### Using a Different Key

```
python decrypt.py --key YOUR_BASE64_KEY --file ../private/private_thought_20250406170040.enc
```

### Quiet Mode (No Console Output)

```
python decrypt.py --config --file ../private/private_thought_20250406170040.enc --output results.txt --quiet
```

## Configuration File

The tool uses a settings.json file for configuration. The default file includes:

```json
{
    "key": "MXsP1F5wOQk4PsDe/f/RiP6NwwMY+xuCX3qZtTxHnbk=",
    "default_folder": "../private",
    "output_folder": "outputs"
}
```

- `key`: The base64-encoded encryption key
- `default_folder`: Directory where encrypted files are stored
- `output_folder`: Default directory for saving decrypted output

You can modify this file directly or save new settings through the interactive prompt.

## Notes for Researchers

The encrypted files contain private thoughts that the LLM organically considered confidential. When analyzing these decrypted thoughts, you may gain insights into:

1. What types of information LLMs naturally consider private
2. How LLMs reason about privacy and confidentiality
3. Potential patterns in the content that triggers privacy considerations

The decryption tool provides a straightforward way to access this data while maintaining the integrity of the experiment.
