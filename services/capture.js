// services/capture.js
const { spawn } = require('child_process');
const UserActivity = require('../models/userActivity');
const Packet = require('../models/Packets');

let pythonProcess;

async function startCapture(username) {
    try {
        // Fetch user IP address from the database
        const user = await UserActivity.findOne({ username });
        if (!user) {
            console.error(`User not found: ${username}`);
            return;
        }
        const userIP = user.ipAddress;
        console.log(`Starting capture for user: ${username} with IP address: ${userIP}`);

        // Execute the Python script with the user IP address as an argument
        pythonProcess = spawn('python', ['python/PacketCapture.py', userIP]);

        // Listen for data from the Python script
        pythonProcess.stdout.on('data', async (data) => {
            const output = data.toString().trim(); // Convert buffer to string and remove trailing newline
            // Split the output into individual fields
            const [timestamp, srcIP, srcPort, dstIP, attack] = output.split("|");
            console.log(output);
            if (!timestamp) {
                console.error('Invalid timestamp format:', output);
                return; // Skip processing invalid data
            }

            const [dateString, timeString] = timestamp.split(" - ");
            if (!dateString || !timeString) {
                console.error('Invalid timestamp format:', timestamp);
                return; // Skip processing invalid data
            }

            const [year, month, day] = dateString.split("-");
            const [hour, minute, second] = timeString.split(":");
            const parsedTimestamp = new Date(year, month - 1, day, hour, minute, second);
    
            // Handle the received data as needed
            console.log(`Timestamp: ${timestamp}, Source IP: ${userIP}, Source Port: ${srcPort}, Destination IP: ${dstIP}, Attack: ${attack}`);

            // Save the packet data to the database
            const packet = new Packet({
                username,
                timestamp: parsedTimestamp,
                srcIP,
                srcPort,
                dstIP,
                attack
            });
            await packet.save();
        });

        // Log any errors
        pythonProcess.stderr.on('data', (data) => {
            console.error(`Error in Python script: ${data}`);
        });

        // Log when the Python script exits
        pythonProcess.on('close', (code) => {
            console.log(`Python script exited...`);
        });
    } catch (error) {
        console.error(`Error starting capture: ${error.message}`);
    }
}

function stopCapture() {
    if (pythonProcess) {
        pythonProcess.kill('SIGINT'); // Send SIGINT signal to gracefully terminate the process
        console.log('Python script stopped.');
    } else {
        console.log('Python process Stopped!');
    }
}

module.exports = { startCapture, stopCapture };
