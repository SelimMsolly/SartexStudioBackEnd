const mongoose = require('mongoose');
const Schema = mongoose.Schema

const UserSchema = new Schema({
    email:String,
    username:String,
    role:String,
    password:String,
    verified: Boolean
})

const User = mongoose.model('User', UserSchema)

module.exports = User