const express = require('express');
const app = express();

app.get('/user', (req, res) => {
  const id = req.query.id;
  db.query('SELECT * FROM users WHERE id = ' + id);
});
