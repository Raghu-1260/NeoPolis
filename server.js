const express = require('express');
const mongoose = require('mongoose');
const path = require('path');
const app = express();

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Connect to your online MongoDB database (Replace with your actual MongoDB Atlas connection string)
const MONGO_URI = process.env.MONGO_URI || "mongodb+srv://<username>:<password>@cluster.mongodb.net/neopolis?retryWrites=true&w=majority";

mongoose.connect(MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => console.log("Connected to MongoDB successfully!"))
    .catch(err => console.error("MongoDB connection error:", err));

// Define User Schema
const UserSchema = new mongoose.Schema({
    username: { type: String, unique: true, required: true },
    pass: { type: String, required: true },
    role: { type: String, required: true }
});
const User = mongoose.model('User', UserSchema);

// Define Plot Schema
const PlotSchema = new mongoose.Schema({
    plotId: { type: String, unique: true, required: true },
    dim: String,
    area: String,
    facing: String,
    status: { type: String, default: "AVAILABLE" },
    owner: { type: String, default: "Unassigned" },
    buyer_mobile: String,
    purchase_date: String
});
const Plot = mongoose.model('Plot', PlotSchema);

// 1. Login Endpoint
app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const user = await User.findOne({ username });
        if (user && user.pass === password) {
            res.json({ success: true, user: { username: user.username, role: user.role } });
        } else {
            res.status(401).json({ success: false, message: "Invalid username or password" });
        }
    } catch (err) {
        res.status(500).json({ success: false, message: "Server error" });
    }
});

// 2. Create User Endpoint (Admin Only)
app.post('/api/users/create', async (req, res) => {
    try {
        const { adminUser, newUsername, newPassword, newRole } = req.body;
        const admin = await User.findOne({ username: adminUser });

        if (admin && admin.role === 'admin') {
            await User.create({ username: newUsername, pass: newPassword, role: newRole });
            res.json({ success: true, message: `Account created for ${newUsername}!` });
        } else {
            res.status(403).json({ success: false, message: "Unauthorized admin action" });
        }
    } catch (err) {
        res.status(400).json({ success: false, message: "User already exists or invalid data" });
    }
});

// 3. Fetch Plots Endpoint
app.get('/api/plots', async (req, res) => {
    try {
        const plotsList = await Plot.find({});
        const plotsMap = {};
        plotsList.forEach(p => { plotsMap[p.plotId] = p; });
        res.json({ success: true, plots: plotsMap });
    } catch (err) {
        res.status(500).json({ success: false, message: "Error fetching plots" });
    }
});

// 4. Update Plot Status Endpoint
app.post('/api/plots/update', async (req, res) => {
    try {
        const { plotId, newStatus, buyerName, buyerMobile } = req.body;
        const purchaseDate = newStatus === 'SOLD' ? new Date().toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' }) : null;

        const updatedPlot = await Plot.findOneAndUpdate(
            { plotId: String(plotId) },
            { 
                status: newStatus, 
                owner: buyerName || "Unassigned", 
                buyer_mobile: buyerMobile || "", 
                purchase_date: purchaseDate 
            },
            { new: true, upsert: true }
        );

        res.json({ success: true, message: `Plot ${plotId} updated successfully!`, updatedPlot });
    } catch (err) {
        res.status(500).json({ success: false, message: "Error updating plot status" });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running online on port ${PORT}`));