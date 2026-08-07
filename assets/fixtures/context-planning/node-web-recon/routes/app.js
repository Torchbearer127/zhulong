const express = require("express");
const app = express();
app.get("/status", (_req, res) => res.send("ok"));
