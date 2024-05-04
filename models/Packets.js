// models/Packets.js
const mongoose = require('mongoose');

const packetSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true
  },
  timestamp: {
    type: Date,
    default: Date.now
  },
  srcIP: String,
  srcPort: String,
  dstIP: String,
  attack: String
});

const Packet = mongoose.model('Packet', packetSchema);

module.exports = Packet;
