const fs = require("fs").promises;
const path = require("path");
const RSAEncryption = require("../factory/rsa");
const AESEncryption = require("../factory/aes");

module.exports = (io) => {
    const clients = new Map();

    io.on("connection", (socket) => {
        console.log("New client connected:", socket.id);

        socket.on("handshake", (data) => {
            console.log(`Handshake received: ${data.senderName}, ${data.bonShared}`);
            const filePath = `./certs/${data.senderName}/private.key`;
            const rsa = new RSAEncryption({ privateKeyFile: filePath });
            const bobSharedKey = rsa.decrypt(data.bonShared);
            const clientId = socket.id;
            clients.set(clientId, {
                senderName: data.senderName,
                key: bobSharedKey,
                chunks: [], // Initialize chunks array for file transfer
            });
            console.log(bobSharedKey);
            socket.emit("handshake_ack", { status: "success" });
        });

        socket.on("secretmsg", (data) => {
            const clientId = socket.id;
            const clientData = clients.get(clientId);
            if (!clientData) {
                socket.emit("error", { message: "secretmsg required" });
                return;
            }

            AESEncryption.decryptData(
                data.secretMsg.encryptedData,
                data.secretMsg.iv,
                clientData.key
            ).then((secretMsg) => {
                console.log("secretMsg: " + secretMsg);
                socket.emit("secretmsg_ack", { status: "success" });
            });
        });

        socket.on("secretfile", (data) => {
            const clientId = socket.id;
            const clientData = clients.get(clientId);
            if (!clientData) {
                socket.emit("error", { message: "secretmsg required" });
                return;
            }

            AESEncryption.decryptFile(
                data.secretFile.encryptedData,
                data.secretFile.iv,
                clientData.key
            ).then((secretFileArrayBuffer) => {
                const ext = path.extname(data.secretFile.fileName);
                const filename = `${data.secretFile.fileName}-${Date.now()}${ext}`;
                fs.writeFile(
                    `./uploads/${filename}`,
                    Buffer.from(secretFileArrayBuffer)
                ).then(() => {
                    console.log("File saved");
                    socket.emit("secretmsg_ack", { status: "success" });
                });
            });
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