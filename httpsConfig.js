const https = require('https');
const fs = require('fs');

const options = {
    key: fs.readFileSync('./server.key'),
    cert: fs.readFileSync('./server.cert')
};

module.exports = {
    createServer: (app, port, hostname) => {
        https.createServer(options, app).listen(port, hostname, () => {
            console.log(`Server running on port ${port}`);
            console.log(`https://${hostname}:${port}/`);
        });
    }
};
