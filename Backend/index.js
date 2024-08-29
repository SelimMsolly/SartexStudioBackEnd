const express = require('express');
const mongoose = require('mongoose');
const app = express();
const cors = require('cors');
const UserRouter = require('./User.js')
const port = 5000

app.use(cors()); // Enable CORS for all routes
app.use(express.json()); // Add this line to parse JSON bodies
app.use('/user', UserRouter) // Use UserRouter for routes under '/user'

// DB connection
mongoose.connect(process.env.DATABASE_URL)
.then(() => {
    console.log("Connected to database");
})
.catch((error) => {
    console.error("Error connecting to database:", error);
});


app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});