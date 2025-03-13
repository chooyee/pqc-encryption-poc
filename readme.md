# PQC Encryption PoC

## Overview
This project is a Proof of Concept (PoC) demonstrating the use of Post-Quantum Cryptography (PQC) for encrypting messages and files in the client browser before transmitting them to the server. The application follows a handshake process where the server provides a public key, and messages/files are encrypted using a combination of ML-KEM (Kyber) for key exchange and AES for message encryption.

## Features
- **Post-Quantum Key Exchange:** Uses ML-KEM (Kyber) to establish a shared secret between the client and server.
- **AES Encryption:** Messages and files are encrypted using AES before transmission.
- **Secure File and Message Transfer:** Ensures confidentiality by encrypting content before sending it over WebSockets.
- **Real-time Monitoring:** Includes a monitoring namespace (`/monitor`) to track message exchanges.

## Architecture
### 1. Handshake Process
- The client initiates a handshake with the server.
- The server responds with a public key.

### 2. Secure Key Exchange
- The client generates a shared secret (`bobshared`).
- This secret is encrypted with the server's ML-KEM public key and sent to the server.
- The server decrypts and stores the shared secret.

### 3. Secure Message & File Transfer
- Messages and files are encrypted using AES with the shared secret.
- The encrypted data is sent to the server.
- The server decrypts the data using AES and processes it accordingly.

## Installation

### Prerequisites
- Node.js (v14 or later)
- npm or yarn

### Setup
1. Clone the repository:
   ```sh
   git clone <repository-url>
   cd pqc-encryption-poc
   ```
2. Install dependencies:
   ```sh
   npm install
   ```
3. Start the server:
   ```sh
   npm start
   ```

## Server Implementation
The backend is implemented using Node.js and Socket.IO.

### Key Components
- **ML-KEM Encryption (Kyber):** Used for key exchange.
- **AES Encryption:** Used for encrypting messages and files.
- **WebSockets (Socket.IO):** Used for real-time communication between the client and server.

### Server Workflow
1. **Handshake:**
   - Generates and shares a public key with the client.
2. **Receiving Encrypted Shared Secret:**
   - Decrypts the shared secret using ML-KEM.
3. **Receiving Encrypted Messages & Files:**
   - Decrypts them using AES.

### Server Code Structure
- `sockets/index.js`: Handles WebSocket communication and encryption logic.
- `factory/mlkem.js`: Implements ML-KEM encryption.
- `factory/aes.js`: Implements AES encryption.
- `uploads/`: Stores received files.

## Client Implementation
The client is implemented using JavaScript with WebSockets.

### Client Workflow
1. Initiates a **handshake** with the server to obtain the public key.
2. Encapsulate  **CipherText** and **shared secret** (`bobshared`) using ML-KEM. This is generated everytime before message or file send.
3. Send the **CipherText** to server
4. Encrypt message or file using AES encryption with **shared secret** (`bobshared`) as key.

### Client Code Structure
- `assets/js/main.js`: Handles encryption and WebSocket communication.
- Uses the WebCrypto API for AES encryption.
- Uses a Kyber library for ML-KEM encryption.

## API Events
### Server Events
| Event Name      | Description |
|----------------|-------------|
| `handshake`    | Client requests the server's public key. |
| `handshake_ack` | Server responds with the public key. |
| `bobshared`    | Client sends the encrypted shared secret. |
| `secretmsg`    | Client sends an encrypted message. |
| `secretfile`   | Client sends an encrypted file. |
| `message_received` | Server forwards received messages to the monitor. |

## Monitoring
A `/monitor` namespace is implemented for tracking real-time message and file exchanges.

## Security Considerations
- **End-to-End Encryption:** Ensures that data remains encrypted during transmission.
- **Post-Quantum Security:** Uses Kyber (ML-KEM) for key exchange.
- **AES Encryption:** Secures message and file content with a strong symmetric cipher.

## Future Enhancements
- Implement hybrid encryption with classical key exchange.
- Add additional security measures for authentication and integrity verification.
- Expand to support more PQC algorithms.

## License
This project is open-source and available under the MIT license.

---

For any questions or contributions, feel free to open an issue or submit a pull request.

