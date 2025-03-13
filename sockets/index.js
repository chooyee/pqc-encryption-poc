const fs = require("fs").promises;
const path = require("path");
const MLKemEncryption = require("../factory/mlkem.js");
const AESEncryption = require("../factory/aes");

module.exports = (io) => {
    const clients = new Map();

    io.on("connection", (socket) => {
        console.log("New client connected:", socket.id);

        socket.on("handshake", async (data) => {
            console.log(`Handshake received: ${data.senderName}, ${data.bonShared}`);
            
            const { publicKey, secretKey } = await MLKemEncryption.generateKeyPair();
            console.log("Public Key:", publicKey);
            console.log("Secret Key:", secretKey);
            const clientId = socket.id;
            clients.set(clientId, {
                senderName: data.senderName,
                key: null,
                chunks: [], // Initialize chunks array for file transfer
                publicKey: publicKey,
                secretKey: secretKey,
            });
           
            socket.emit("handshake_ack", { status: "success",publicKey: publicKey });
        });

        socket.on("secretmsg", async (data, callback) => {
            const clientId = socket.id;
            const clientData = clients.get(clientId);
            if (!clientData) {
                callback({status:"failed", message: `Client Id [${socket.id}] does not exists!` });
                return;
            }

            try {
                const secretMsg = await AESEncryption.decryptData(
                    data.secretMsg.encryptedData,
                    data.secretMsg.iv,
                    clientData.key
                );
                console.log("secretMsg: " + secretMsg);
                callback({ status: "success" });
            } catch (error) {
                console.error("Decryption error:", error);
                callback({ status: "error", message: "Failed to decrypt message" });
            }
        });

        socket.on("bobshared", (data, callback) => {
            const clientId = socket.id;
            const clientData = clients.get(clientId);
            if (!clientData) {
                callback({status:"failed", message: `Client Id [${socket.id}] does not exists!` });
                return;
            };

            MLKemEncryption.decrypt(data.cipherText, clientData.secretKey).then((sharedSecret) => {
                console.log("Shared Secret: " + sharedSecret);
                clientData.key = sharedSecret;
                callback({ status: "success" });
            });
            
        });

        socket.on("secretfile", async (data, callback) => {
            const clientId = socket.id;
            const clientData = clients.get(clientId);
            if (!clientData) {
                callback({status:"failed", message: `Client Id [${socket.id}] does not exists!` });
                return;
            }

            try {
                const secretFileArrayBuffer = await AESEncryption.decryptFile(
                    data.secretFile.encryptedData,
                    data.secretFile.iv,
                    clientData.key
                );
                
                const ext = path.extname(data.secretFile.fileName);
                const filename = `${data.secretFile.fileName}-${Date.now()}${ext}`;
                
                await fs.writeFile(
                    `./uploads/${filename}`,
                    Buffer.from(secretFileArrayBuffer)
                );
                
                console.log("File saved");
                //socket.emit("file_received_ack", { status: "success", fileName: filename });
                callback({status:"success", fileName: filename });
            } catch (error) {
                console.error("Error processing file:", error);
                socket.emit("error", { message: "Failed to process file" });
            }
        });

        socket.on("chunk", (data) => {
            const clientId = socket.id;
            const clientData = clients.get(clientId);
            if (!clientData) {
                socket.emit("error", { message: "Handshake required" });
                return;
            }

            const chunk = Buffer.isBuffer(data.chunk)
                ? data.chunk
                : Buffer.from(data.chunk, "base64");
            clientData.chunks.push(chunk);
            console.log(`Received chunk #${clientData.chunks.length}`);
        });

        socket.on("end", () => {
            const clientId = socket.id;
            const clientData = clients.get(clientId);
            if (!clientData) {
                socket.emit("error", { message: "No client data" });
                return;
            }

            const outputPath = path.join(__dirname, "../../uploads", `${clientData.fileName}`);
            const fullFile = Buffer.concat(clientData.chunks);
            fs.writeFileSync(outputPath, fullFile);
            console.log(`File saved: ${outputPath}`);

            socket.emit("file_received", { fileName: clientData.fileName });
            clients.delete(clientId);
        });

        socket.on("disconnect", () => {
            const clientId = socket.id;
            clients.delete(clientId);
            console.log("Client disconnected:", clientId);
        });

        socket.on("error", (err) => {
            console.error("Socket.IO error:", err);
        });
    });
};