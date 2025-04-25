import mongoose from "mongoose";

const userSchema = new mongoose.Schema({
    name: {
        required: true,
        type: String
    },
    email: {
        required: true,
        type: String,
        unique: true,
    },
    password: {
        required: true,
        type: String,
    },
    photoUrl: {
        type: String,
    },
    totalLeaves: {
        type: Number,
        default: 6
    },
    leavesUsed: {
        type: Number,
        default: 0
    }
})

const User = mongoose.model('User', userSchema);
export default User;