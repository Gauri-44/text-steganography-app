import streamlit as st
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
from base64 import b64encode, b64decode

# Helper functions for encryption and decryption
def encrypt_message(secret_message, secret_key):
    # Convert key and message to bytes
    key = secret_key.encode('utf-8').ljust(32)[:32]  # Ensure 32-byte key
    message = secret_message.encode('utf-8')

    # Generate a random initialization vector (IV)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message) + encryptor.finalize()

    # Return IV and encrypted message as base64-encoded strings
    return b64encode(iv).decode('utf-8'), b64encode(ciphertext).decode('utf-8')

def decrypt_message(iv, ciphertext, secret_key):
    # Convert key, IV, and ciphertext to bytes
    key = secret_key.encode('utf-8').ljust(32)[:32]  # Ensure 32-byte key
    iv = b64decode(iv)
    ciphertext = b64decode(ciphertext)

    # Decrypt the message
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    return plaintext.decode('utf-8')

# Encoding and decoding functions with encryption/decryption
def encode_text(file_content, secret_text, secret_key):
    try:
        # Encrypt the secret text
        iv, encrypted_message = encrypt_message(secret_text, secret_key)
        
        # Combine IV and encrypted message
        hidden_data = f"{iv}::{encrypted_message}"
        
        # Convert hidden data to invisible characters
        invisible_data = ''.join(chr(0x200B) + char for char in hidden_data)  # Zero-width space prefix
        
        # Append invisible characters to the file content
        encoded_data = file_content + invisible_data
        return encoded_data
    except Exception as e:
        raise Exception(f"Error during encoding: {str(e)}")


def decode_text(file_content, secret_key):
    try:
        # Extract hidden data (invisible characters)
        hidden_data = ''.join(char for char in file_content if char == chr(0x200B) or ord(char) > 0x200B)
        visible_data = ''.join(char for char in hidden_data if char != chr(0x200B))  # Remove zero-width spaces
        
        # Split into IV and encrypted message
        if "::" not in visible_data:
            raise ValueError("No encoded message found!")
        iv, encrypted_message = visible_data.split("::", 1)
        
        # Decrypt the message
        try:
            secret_text = decrypt_message(iv, encrypted_message, secret_key)
            return secret_text
        except Exception:
            raise ValueError("Wrong secret key!")
    except Exception as e:
        raise Exception(f"Error during decoding: {str(e)}")



# Streamlit app
def main():
    st.title("Text Steganography with Encryption")
    st.sidebar.title("Options")
    app_mode = st.sidebar.radio("Select Mode", ["Encode", "Decode"])

    if app_mode == "Encode":
        st.header("Encode Secret Message into Text File")
        uploaded_file = st.file_uploader("Upload Text File", type="txt")
        secret_text = st.text_area("Enter Secret Text to Hide")
        secret_key = st.text_input("Enter Secret Key (for encryption)", type="password")
        if st.button("Encode"):
            if not uploaded_file or not secret_text or not secret_key:
                st.warning("Please fill in all fields!")
            else:
                try:
                    file_content = uploaded_file.read().decode("utf-8")
                    encoded_data = encode_text(file_content, secret_text, secret_key)

                    # Save the encoded file
                    encoded_file_name = uploaded_file.name.replace(".txt", "_encoded.txt")
                    st.download_button(
                        label="Download Encoded File",
                        data=encoded_data,
                        file_name=encoded_file_name,
                        mime="text/plain",
                    )
                    st.success(f"File encoded successfully! Download your file using the button above.")
                except Exception as e:
                    st.error(f"Error: {str(e)}")

    elif app_mode == "Decode":
        st.header("Decode Secret Message from Text File")
        uploaded_file = st.file_uploader("Upload Encoded Text File", type="txt")
        secret_key = st.text_input("Enter Secret Key (for decryption)", type="password")
        if st.button("Decode"):
            if not uploaded_file or not secret_key:
                st.warning("Please fill in all fields!")
            else:
                try:
                    file_content = uploaded_file.read().decode("utf-8")
                    secret_text = decode_text(file_content, secret_key)
                    st.success(f"Decoded Secret Message: {secret_text}")

                    # Save the decoded message
                    decoded_file_name = "decoded_message.txt"
                    st.download_button(
                        label="Download Decoded Message",
                        data=secret_text,
                        file_name=decoded_file_name,
                        mime="text/plain",
                    )
                except Exception as e:
                    st.error(f"Error: {str(e)}")

if __name__ == "__main__":
    main()
