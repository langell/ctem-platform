const express = require('express');
const { execFile } = require('child_process');
const app = express();

app.get('/user', (req, res) => {
  db.query('SELECT * FROM users WHERE id = $1', [req.query.id]);
});

app.get('/run', (req, res) => {
  execFile('ls', [req.query.dir]);
});

const password = process.env.DB_PASSWORD;
