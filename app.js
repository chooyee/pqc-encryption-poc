const express = require("express");
const http = require("http");
const path = require("path");
const { Server } = require("socket.io");
const { corsOptions } = require("./config/cors");
const errorHandler = require("./middleware/errorHandler");
const indexRoutes = require("./routes/index");
const apiRoutes = require("./routes/api");
const initializeSocket = require("./sockets/index");

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: corsOptions });

// Middleware
app.use(express.static("./public"));
app.use(express.json());
app.use(express.urlencoded({ limit: "50mb", extended: true }));
app.set("views", path.join(__dirname, "./views"));
app.set("view engine", "ejs");

if (app.get("env") === "production") {
  app.set("trust proxy", 1);
  // Assuming session middleware is used; otherwise, remove this block
  // sess.cookie.secure = true;
}

// Routes
app.use("/", indexRoutes);
app.use("/", apiRoutes);

// Error handling
app.use(errorHandler);

// Socket.IO
initializeSocket(io);

// Start server
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`);
});



// (async () => {
//     const MLKemEncryption = require("./factory/mlkem.js");
//     const { publicKey, secretKey } = await MLKemEncryption.generateKeyPair();
//     console.log("Public Key:", publicKey);
//     console.log("Secret Key:", secretKey);
// })();