# Double Ratchet Algorithm Implementation

This repository implements the Double Ratchet algorithm, a cryptographic protocol that ensures secure end-to-end encryption with forward and backward secrecy. It combines symmetric-key and Diffie-Hellman (DH) ratchets for robust key management during communication.

## Features
- **End-to-End Encryption**: Secure message encryption using unique keys for each message.
- **Forward and Backward Secrecy**: Protects past and future messages even if current keys are compromised.
- **Out-of-Order Message Handling**: Efficient management of delayed or skipped messages.
- **X3DH Integration**: Utilizes the X3DH protocol for initial key agreement.

## Components
- **Symmetric-Key Ratchet**: Derives unique keys for encrypting and decrypting messages.
- **Diffie-Hellman Ratchet**: Periodically updates key material for enhanced security.
- **Initialization**: Establishes shared keys using the X3DH key agreement protocol.

## Getting Started
   ```bash
   git clone https://github.com/prateek21081/ratchet-chat.git
   cd ratchet-chat
   pip install -r requirements.txt
   python chat.py --peer-ip <IP>
