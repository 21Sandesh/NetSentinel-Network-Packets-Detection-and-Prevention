// models/userActivity.js
const mongoose = require('mongoose');

const userActivitySchema = new mongoose.Schema({
    username: {
        type: String,
        required: true
    },
    ipAddress: {
        type: String,
        required: true
    },
    port: {
        type: Number,
        required: true
    },
    action: {
        type: String,
        enum: ['login', 'logout', 'signup'],
        required: true
    },
    timestamp: {
        type: Date,
        default: Date.now
    }
});

const UserActivity = mongoose.model('UserActivity', userActivitySchema);

module.exports = UserActivity;
