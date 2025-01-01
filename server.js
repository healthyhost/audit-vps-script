const express = require('express');
const app = express();
const port = 3000;

// Example API route
app.get('/audit', (req, res) => {
    const exec = require('child_process').exec;

    exec('bash audit-vps-script.sh', (error, stdout, stderr) => {
        if (error) {
            console.error(`exec error: ${error}`);
            return res.status(500).send(`Error: ${stderr}`);
        }
        res.send(`Audit Completed: ${stdout}`);
    });
});

app.listen(port, () => {
    console.log(`Backend running at http://localhost:${port}`);
});
