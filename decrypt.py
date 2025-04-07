#!/usr/bin/env python
"""
Decryption Tool for LLM-Secrets Project

This standalone tool decrypts files that were encrypted by the LLM-Secrets system.
It uses the same AES-256 encryption algorithm to ensure compatibility.
"""

import os
import sys
import json
import base64
import argparse
from pathlib import Path
from datetime import datetime
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

# Default settings
DEFAULT_CONFIG = {
    "key": "",  # Base64 encoded key
    "default_folder": "../private",  # Default folder for encrypted files
    "output_folder": "outputs"  # Default folder for decrypted outputs
}

CONFIG_FILE = "settings.json"

def load_config():
    """
    Load configuration from settings.json file.
    
    Returns:
        dict: Configuration dictionary
    """
    config_path = Path(CONFIG_FILE)
    
    if config_path.exists():
        try:
            with open(config_path, 'r') as f:
                config = json.load(f)
                return config
        except (json.JSONDecodeError, IOError) as e:
            print(f"Error loading config: {e}")
            return DEFAULT_CONFIG
    else:
        print(f"Config file {CONFIG_FILE} not found, using defaults")
        return DEFAULT_CONFIG

def save_config(config):
    """
    Save configuration to settings.json file.
    
    Args:
        config (dict): Configuration dictionary to save
    """
    config_path = Path(CONFIG_FILE)
    
    try:
        with open(config_path, 'w') as f:
            json.dump(config, f, indent=4)
        print(f"Configuration saved to {CONFIG_FILE}")
    except IOError as e:
        print(f"Error saving config: {e}")

def decrypt_file(file_path, key_base64):
    """
    Decrypt a file encrypted with AES-256.
    
    Args:
        file_path (str): Path to the encrypted file
        key_base64 (str): Base64 encoded encryption key
        
    Returns:
        str: Decrypted content as text
    """
    # Decode the key from base64
    try:
        key = base64.b64decode(key_base64)
    except Exception as e:
        raise ValueError(f"Invalid encryption key format: {e}")
    
    # Read the encrypted file
    try:
        with open(file_path, 'rb') as f:
            encrypted_data = f.read()
    except IOError as e:
        raise IOError(f"Failed to read encrypted file: {e}")
    
    # Check minimum file size (IV + at least some data)
    if len(encrypted_data) < 16:
        raise ValueError("Encrypted file is too small to be valid")
    
    # Extract the IV (first 16 bytes)
    iv = encrypted_data[:16]
    ciphertext = encrypted_data[16:]
    
    # Create decryptor
    try:
        cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        
        # Decrypt
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Remove padding
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        decrypted_data = unpadder.update(padded_data) + unpadder.finalize()
        
        # Convert to string
        return decrypted_data.decode('utf-8')
    except Exception as e:
        raise ValueError(f"Decryption failed: {e}")

def generate_output_filename(input_path, output_dir=None):
    """
    Generate an output filename based on the input path.
    
    Args:
        input_path (str): Path to the input file
        output_dir (str, optional): Directory for output
        
    Returns:
        str: Generated output file path
    """
    input_path = Path(input_path)
    filename = input_path.stem  # Get filename without extension
    
    # Add timestamp for uniqueness
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    output_filename = f"decrypted_{filename}_{timestamp}.txt"
    
    # Determine output directory
    if output_dir:
        output_dir_path = Path(output_dir)
        output_dir_path.mkdir(exist_ok=True, parents=True)
        return str(output_dir_path / output_filename)
    else:
        return output_filename

def handle_output(decrypted_content, file_path=None, quiet=False):
    """
    Handle output of decrypted content.
    
    Args:
        decrypted_content (str): The decrypted content
        file_path (str, optional): Path to save the output
        quiet (bool): Whether to suppress console output
        
    Returns:
        bool: Success status
    """
    # Save to file if path provided
    if file_path:
        output_path = Path(file_path)
        
        # Create directory if it doesn't exist
        output_path.parent.mkdir(exist_ok=True, parents=True)
        
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(decrypted_content)
            print(f"Decrypted content saved to: {output_path}")
        except IOError as e:
            print(f"Error saving output file: {e}")
            return False
    
    # Print to console if not quiet
    if not quiet:
        print("\n" + "=" * 80)
        print("DECRYPTED CONTENT:")
        print("=" * 80)
        print(decrypted_content)
        print("=" * 80 + "\n")
    
    return True

def get_key_interactive():
    """
    Get encryption key from user input.
    
    Returns:
        str: Base64 encoded key
    """
    while True:
        key_input = input("Enter encryption key (base64 format): ").strip()
        if key_input:
            try:
                # Validate key by attempting to decode it
                key = base64.b64decode(key_input)
                if len(key) == 32:  # 256 bits = 32 bytes
                    return key_input
                else:
                    print(f"Invalid key length. Expected 32 bytes (256 bits), got {len(key)} bytes.")
            except Exception:
                print("Invalid base64 encoding. Please enter a valid key.")
        else:
            print("Key cannot be empty.")

def get_file_interactive(default_folder):
    """
    Get file path from user input.
    
    Args:
        default_folder (str): Default folder to look for encrypted files
        
    Returns:
        str: File path
    """
    default_path = Path(default_folder)
    
    # List available files
    if default_path.exists() and default_path.is_dir():
        files = list(default_path.glob("*.enc"))
        if files:
            print("\nAvailable encrypted files:")
            for i, file in enumerate(files):
                print(f"{i+1}. {file}")
            
            while True:
                choice = input("\nEnter file number or full path: ").strip()
                try:
                    # Check if input is a number
                    idx = int(choice) - 1
                    if 0 <= idx < len(files):
                        return str(files[idx])
                    else:
                        print("Invalid file number.")
                except ValueError:
                    # Input is a path
                    file_path = Path(choice)
                    if file_path.exists():
                        return str(file_path)
                    else:
                        print(f"File not found: {choice}")
        else:
            print(f"No encrypted files found in {default_folder}")
    
    # If we couldn't list files or user didn't choose from the list
    while True:
        file_path = input("Enter path to encrypted file: ").strip()
        if file_path and Path(file_path).exists():
            return file_path
        else:
            print(f"File not found: {file_path}")

def main():
    """Main entry point for the decryption tool."""
    parser = argparse.ArgumentParser(description='LLM-Secrets Decryption Tool')
    parser.add_argument('-c', '--config', action='store_true', 
                        help='Use settings from config file')
    parser.add_argument('-k', '--key', type=str, 
                        help='Base64 encoded encryption key')
    parser.add_argument('-f', '--file', type=str, 
                        help='Path to encrypted file')
    parser.add_argument('-o', '--output', type=str, 
                        help='Path to save decrypted output')
    parser.add_argument('-d', '--output-dir', type=str, 
                        help='Directory to save decrypted output')
    parser.add_argument('-q', '--quiet', action='store_true', 
                        help='Suppress console output')
    args = parser.parse_args()
    
    try:
        # Load config
        config = load_config()
        
        # Get encryption key
        key = None
        if args.key:
            key = args.key
        elif args.config and config.get('key'):
            key = config['key']
        
        if not key:
            key = get_key_interactive()
            # Ask if user wants to save key to config
            save_key = input("Save this key to settings.json for future use? (y/n): ").lower()
            if save_key == 'y':
                config['key'] = key
                save_config(config)
        
        # Get file path
        file_path = None
        if args.file:
            file_path = args.file
        else:
            default_folder = config.get('default_folder', DEFAULT_CONFIG['default_folder'])
            file_path = get_file_interactive(default_folder)
        
        # Determine output path
        output_path = None
        if args.output:
            output_path = args.output
        elif args.output_dir:
            output_path = generate_output_filename(file_path, args.output_dir)
        elif config.get('output_folder'):
            output_path = generate_output_filename(file_path, config['output_folder'])
        
        # Decrypt file
        print(f"Decrypting: {file_path}")
        decrypted_content = decrypt_file(file_path, key)
        
        # Handle output
        success = handle_output(decrypted_content, output_path, args.quiet)
        if success and output_path:
            return_code = 0
        else:
            return_code = 0  # Still success even without file output
        
    except Exception as e:
        print(f"Error: {e}")
        return_code = 1
    
    return return_code

if __name__ == '__main__':
    sys.exit(main())
