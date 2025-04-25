import jwt from 'jsonwebtoken';
import User from '../database/user.schema.js';
import redis from "redis";

const redisClient = redis.createClient();

redisClient.on('error', (err) => console.log('Redis Client Error', err));
(async () => {
       try {
        await redisClient.connect();
        console.log('Redis connected successfully');
    } catch (err) {
        console.error('Redis connection failed:', err);
    }
})();

const authenticate = async (req, res, next) => {
    try {
        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({
                success: false,
                message: "Authorization token required (Bearer token)"
            });
        }

        const token = authHeader.split(' ')[1];
        const decoded = jwt.verify(token, process.env.JWT_SECRET);

        const redisKey = `user:${decoded.userId}`;
        const cachedUser = await redisClient.get(redisKey);
        if(cachedUser){
            console.log(`Serving from Redis`);
            const user = JSON.parse(cachedUser);
            req.user = {
                id: user.id,
                email: user.email,
                role: user.role
            };
            return next();
        }

        console.log("Fetching from Postgres");
        const user = await User.findOne(decoded.userId);
        if (!user) {
            return res.status(401).json({
                success: false,
                message: "User not found - token invalid"
            });
        }

        // Cache the user data in Redis
        await redisClient.setEx(
            redisKey,
            30, // 5 minutes (300 seconds)
            JSON.stringify({
                id: user.id,
                email: user.email,
                role: user.role
            })
        );

        req.user = {
            id: user.id,
            email: user.email,
        };

        next();
    } catch (error) {
        if (error instanceof jwt.TokenExpiredError) {
            return res.status(401).json({
                success: false,
                message: "Token expired",
                code: "TOKEN_EXPIRED"
            });
        }

        if (error instanceof jwt.JsonWebTokenError) {
            return res.status(401).json({
                success: false,
                message: "Invalid token",
                code: "INVALID_TOKEN"
            });
        }

        console.error("Authentication error:", error);
        res.status(500).json({
            success: false,
            message: "Internal authentication error"
        });
    }
};


export { authenticate };
