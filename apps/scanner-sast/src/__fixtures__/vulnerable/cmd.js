const { exec } = require('child_process');

app.get('/run', (req, res) => {
  const dir = req.query.dir;
  exec('ls ' + dir);
});
