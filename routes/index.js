const express = require("express");
const router = express.Router();

router.get("/ping", (req, res) => {
  res.status(200).send("pong");
});

router.get("/", (req, res) => {
  const hostname =
    process.env.ENVIRONMENT === "dev"
      ? `${req.protocol}://${req.header("host")}`
      : `${req.protocol}://${req.hostname}`;
  res.render("index");
});

module.exports = router;