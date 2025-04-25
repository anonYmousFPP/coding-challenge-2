import express from "express";
import mongoose from "mongoose";
import fileUpload from "express-fileupload";
import morgan from "morgan";
import logger from "./utils/logger.js";
import swaggerUi from "swagger-ui-express";
import swaggerJsdoc from "swagger-jsdoc";
import swaggerConfig from "./swagger.js"; 
import dotenv from "dotenv"
dotenv.config();
const MONGO = process.env.MONGO_URL;
mongoose.connect(MONGO);


import authRoute from "./routes/auth.route.js";
import leaveRoute from "./routes/leave.routes.js";

const app = express();
app.use(express.json());

app.use(fileUpload({
    useTempFiles: true
}));

app.use(morgan('combined', { stream: logger.stream }));
const swaggerSpec = swaggerJsdoc(swaggerConfig);
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec));

app.use((err, req, res, next) => {
    logger.error(err.stack);
    res.status(500).send('Something broke!');
});

app.get('/', (req, res) => {
    res.send("hey bro");
})

app.use('/users/api/v1', authRoute);
app.use('/users/api/v1/leave', leaveRoute);

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});