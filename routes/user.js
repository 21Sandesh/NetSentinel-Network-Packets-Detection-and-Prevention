// routes/user.js
const express = require('express');
const router = express.Router();
const { getUser } = require('../services/auth');
const { startCapture } = require('../services/capture');
const Packet = require('../models/Packets');
const {restrictAccess} = require('../middlewares/auth');
const { handleUserLogout } = require('../controllers/user');
const UserActivity = require('../models/userActivity');
const User = require('../models/user');
const bcrypt = require('bcrypt');

router.get('/dashboard', async (req, res) => {
    const sessionID = req.cookies.sessionID;
    const user = getUser(sessionID);
    try {
        // Fetch packets data for the logged-in user
        const username = user.username;
        const packets = await Packet.find({ username: username });

        // Extract _id field from each packet
        const packetIds = packets.map(packet => packet._id);

        // Start packet capture for the logged-in user
        startCapture(username);

        // Fetch user activity data
        const userActivity = await UserActivity.findOne({ username: username, action: 'login' });

        // Calculate total packets count
        const totalPacketsCount = packets.length;

        // Fetch user's first name and last name
        const userData = await User.findOne({ username: username });

        // Combine first name and last name if they exist, otherwise use username
        let name = username; // Default to username
        if (userData && userData.firstName && userData.lastName) {
            name = `${userData.firstName} ${userData.lastName}`;
        }

        // Calculate the count of non-normal attacks
        const nonNormalAttacksCount = packets.reduce((count, packet) => {
        if (packet.attack !== 'normal.') {
            count++;
        }
        return count;
    }, 0);

    // Format timestamps in packets
    const formattedPackets = packets.map(packet => {
        const timestamp = packet.timestamp;
        const date = timestamp.toDateString();
        const time = timestamp.toTimeString().split(' ')[0]; // Extracting time part and removing timezone
        return {
            ...packet.toObject(), // Convert Mongoose document to plain JavaScript object
            date,
            time
        };
    });

    // Render the dashboard view with packets data
    res.render('dashboard', { 
      username: username, 
      packets: formattedPackets, 
      packetsIds: packetIds,
      userIP: userActivity ? userActivity.ipAddress : null,
      totalPacketsCount: totalPacketsCount,
      name: name,
      nonNormalAttacksCount: nonNormalAttacksCount,
      email: userData.email
    });
  } catch (err) {
    console.error(err);
    res.status(500).send('Server Error');
  }
});

router.get('/logout', restrictAccess, handleUserLogout);

// GET settings page
router.get('/settings', (req, res) => {
    // Render the settings page
    res.render('settings', { user: req.user });
});

// POST update user name
router.post('/settings/changeName', async (req, res) => {
    try {
        const { firstName, lastName, currentPassword } = req.body;
        
        // Verify current password
        const user = req.user;
        const isPasswordValid = await bcrypt.compare(currentPassword, user.password);
        if (!isPasswordValid) {
            req.flash('error', 'Current password is incorrect');
            return res.redirect('/user/settings');
        }

        // Update user's first name and last name
        user.firstName = firstName || user.firstName;
        user.lastName = lastName || user.lastName;

        await user.save();

        // Redirect back to settings page with success message
        req.flash('success', 'Name updated successfully');
        res.redirect('/user/settings');
    } catch (error) {
        // Handle errors
        console.error(error);
        res.status(500).send('Internal Server Error');
    }
});

// POST update user password
router.post('/settings/changePassword', async (req, res) => {
    try {
        const { newPassword, confirmPassword, currentPassword } = req.body;
        
        // Verify current password
        const user = req.user;
        const isPasswordValid = await bcrypt.compare(currentPassword, user.password);
        if (!isPasswordValid) {
            req.flash('error', 'Current password is incorrect');
            return res.redirect('/user/settings');
        }

        // Check if new password matches confirm password
        if (newPassword !== confirmPassword) {
            req.flash('error', 'New password and confirm password do not match');
            return res.redirect('/user/settings');
        }

        // Update user's password
        const hashedPassword = await bcrypt.hash(newPassword, 10);
        user.password = hashedPassword;

        await user.save();

        // Redirect back to settings page with success message
        req.flash('success', 'Password updated successfully');
        res.redirect('/user/settings');
    } catch (error) {
        // Handle errors
        console.error(error);
        res.status(500).send('Internal Server Error');
    }
});

// POST route to delete selected packets
router.post('/deletePackets', async (req, res) => {
    try {
        const packetIdsToDelete = req.body.packetIds;

        // Delete packets from the database
        await Packet.deleteMany({ _id: { $in: packetIdsToDelete } });
        req.flash('success', 'Packets deleted successfully');
        res.sendStatus(200);
    } catch (error) {
        console.error(error);
        res.status(500).send('Internal Server Error');
    }
});


module.exports = router;
