const express = require("express");
const router = express.Router();
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const certManager = require("../factory/certManager");

// Multer configuration
const maxSize = 100 * 1000 * 1000;
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, "uploads"),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    cb(null, `${file.originalname.replace(ext, "")}-${Date.now()}${ext}`);
  },
});

const upload = multer({
  storage,
  limits: { fileSize: maxSize },
});

// Routes
router.post("/upload", upload.single("file"), (req, res) => {
  console.log(req.body.userid);
  console.log(req.file);
  res.status(200).send({ status: "success", message: "" });
});

router.post("/api/v1/cert/new", (req, res) => {
  const certGen = new certManager({
    id: req.body.id,
    commonName: req.body.commonName,
    validityYears: req.body.validityYears,
    altNames: req.body.altNames,
  });

  const certData = certGen.generate();
  certGen.saveToFiles("./certs/");
  console.log("Certificates saved successfully");
  res.status(200).send({ status: "success", message: certData.publicKey });
});

router.get("/api/v1/cert/get/:id", (req, res) => {
  const filePath = `./certs/${req.params.id}/public.key`;
  fs.readFile(filePath, { encoding: "utf-8" }, (err, data) => {
    if (!err) {
      res.writeHead(200, { "Content-Type": "text" });
      res.write(data);
      res.end();
    } else {
      console.log(err);
      res.status(500).send("Error reading certificate");
    }
  });
});

module.exports = router;