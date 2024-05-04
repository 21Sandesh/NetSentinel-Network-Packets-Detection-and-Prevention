const mongoose = require('mongoose');

async function connecttoMongoDB(url){
    return mongoose.connect(url);
}

module.exports = {
    connecttoMongoDB,
};