const fs = require('fs');
const path = require('path');

async function mlResults(req, res) {
    const jsonFilePath = path.join(__dirname, '..', 'python', 'result.json');
    fs.readFile(jsonFilePath, 'utf8', (err, data) => {
        if (err) {
            console.error(err);
            return res.status(500).send('Error reading JSON file');
        }

        const jsonData = JSON.parse(data);
        // Extract algorithm names
        const algorithms = Object.keys(jsonData).filter(key => key !== 'Algorithm');
        const results = [];
        algorithms.forEach(algorithm => {
            const scores = jsonData[algorithm];
            results.push({ algorithm: algorithm, scores: scores });
        });

        // Render result.ejs with results
        res.render('result', { results: results });
    });
}

module.exports = {
    mlResults
};
