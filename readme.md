User and Leave Management API
This is a RESTful API built with Node.js and Express.js for user authentication, profile management, and leave application management. It includes features like user signup/login, password reset with OTP, profile updates with photo upload, and leave application submission/tracking. The API is documented using Swagger (OpenAPI 3.0) and hosted at /api-docs.
Technologies Used

Node.js: JavaScript runtime for server-side development.
Express.js: Web framework for building RESTful APIs.
MongoDB: NoSQL database for storing user and leave data.
Mongoose: ODM for MongoDB to manage schemas and queries.
JWT (jsonwebtoken): For secure user authentication with tokens.
Bcrypt: For password hashing.
Nodemailer: For sending OTP emails during password reset.
Cloudinary: For uploading and managing user profile photos.
Express-fileupload: For handling file uploads.
Morgan: For HTTP request logging.
Winston & Winston-daily-rotate-file: For advanced logging with daily rotation.
Swagger-ui-express & Swagger-jsdoc: For API documentation and interactive UI.
Dotenv: For managing environment variables.
Crypto: For generating OTPs and reset tokens.

Installation

Clone the Repository:
git clone https://github.com/anonYmousFPP/coding-challenge-2.git
cd coding-challenge-2


Install Dependencies:Ensure Node.js (v16 or higher) is installed. Then, install all required packages:
npm install

This installs:

express
mongoose
express-fileupload
morgan
winston
winston-daily-rotate-file
jsonwebtoken
bcrypt
nodemailer
cloudinary
dotenv
swagger-ui-express
swagger-jsdoc



Configuration

Create a .env File:In the project root, create a .env file and add the following environment variables:
MONGO_URL=your_mongodb_connection_string
PORT=3000
JWT_SECRET=your_jwt_secret
CLOUDINARY_CLOUD_NAME=your_cloudinary_cloud_name
CLOUDINARY_API_KEY=your_cloudinary_api_key
CLOUDINARY_API_SECRET=your_cloudinary_api_secret
EMAIL_USERNAME=your_email_username
EMAIL_PASSWORD=your_email_password


MONGO_URL: MongoDB connection string (e.g., mongodb://localhost:27017/your_database or a MongoDB Atlas URI).
PORT: Port for the server (default: 3000).
JWT_SECRET: Secret key for JWT signing (e.g., a random string).
CLOUDINARY_*: Credentials from your Cloudinary account (sign up at cloudinary.com).
EMAIL_USERNAME/PASSWORD: Gmail credentials or app-specific password for Nodemailer (enable 2FA and generate an app password if needed).


Create Logs Directory:Ensure the logs/ directory exists for logging:
mkdir logs



Running the Application

Start the Server:
npm start

This runs node index.js, starting the server on the port specified in .env (default: 3000).

Access the API:

Base URL: http://localhost:3000/users/api/v1
Swagger UI: http://localhost:3000/api-docs


Test Endpoints:Use tools like Postman, cURL, or the Swagger UI to test endpoints. Start with /users/api/v1/login to obtain a JWT token, then use it for authenticated routes.


Swagger Documentation
The API is documented using Swagger (OpenAPI 3.0). Access the interactive Swagger UI at:
http://localhost:3000/api-docs

Swagger UI Screenshot
Below is a screenshot of the Swagger UI showing all API endpoints:

To add the screenshot:

Run the application (npm start).
Open http://localhost:3000/api-docs in your browser.
Take a screenshot of the Swagger UI.
Save it as swagger-screenshot.png in a docs/ directory (create it with mkdir docs).
Ensure the path in the README.md (./docs/swagger-screenshot.png) is correct.

The Swagger UI includes:

Authentication Endpoints: Login, signup, password reset (forget-password, send-otp, verify-otp).
User Endpoints: Get and update user profile.
Leave Endpoints: Submit, list, and view leave applications.

Project Structure
project-root/
├── database/                   # Mongoose schemas
│   ├── user.schema.js
│   ├── leave.schema.js
├── routes/                     # API route handlers
│   ├── auth.route.js
│   ├── leave.routes.js
├── utils/                      # Utility modules
│   ├── logger.js
├── middleware/                 # middleware
│   ├── user.middleware.js
├── validators/                 # Request validation
│   ├── auth.validators.js
├── logs/                       # Log files
│   ├── application-*.log
│   ├── exceptions-*.log
├── docs/                       # Documentation assets
│   ├── swagger-screenshot.png
├── .env                        # Environment variables
├── index.js                    # Main application file
├── swagger.js                  # Swagger configuration
├── package.json
└── node_modules/

API Endpoints
Authentication

POST /users/api/v1/login: Authenticate a user and return a JWT token.
POST /users/api/v1/signup: Register a new user with a profile photo.
POST /users/api/v1/forget-password: Initiate password reset and get a reset token.
POST /users/api/v1/send-otp: Send OTP to the user’s email for password reset.
POST /users/api/v1/verify-otp: Verify OTP and update the password.

User

GET /users/api/v1/profile: Retrieve the authenticated user’s profile (requires JWT).
PATCH /users/api/v1/profile: Update the user’s name or photo (requires JWT).

Leave

POST /users/api/v1/leave: Submit a leave application (requires JWT).
GET /users/api/v1/leave: List leave applications with pagination and filters (requires JWT).
GET /users/api/v1/leave/{leaveId}: Get details of a specific leave application (requires JWT).

Explore all endpoints in the Swagger UI for detailed request/response schemas.
Troubleshooting

Swagger UI Not Loading:

Ensure swagger-ui-express and swagger-jsdoc are installed (npm install swagger-ui-express swagger-jsdoc).
Check swagger.js for syntax errors.
Verify the server is running and access http://localhost:3000/api-docs.


MongoDB Connection Errors:

Confirm MONGO_URL in .env is correct and MongoDB is running.
For MongoDB Atlas, ensure your IP is whitelisted.


Cloudinary Upload Fails:

Verify CLOUDINARY_CLOUD_NAME, CLOUDINARY_API_KEY, and CLOUDINARY_API_SECRET in .env.
Check network connectivity and Cloudinary account status.


Nodemailer Email Issues:

Ensure EMAIL_USERNAME and EMAIL_PASSWORD are correct.
For Gmail, enable 2FA and use an app-specific password.


Logs Not Generating:

Ensure the logs/ directory exists (mkdir logs).
Check logger.js for configuration issues.


General Errors:

Review logs in logs/application-*.log and logs/exceptions-*.log.
Run npm install to ensure all dependencies are installed.



Contributing
Contributions are welcome! Please:

Fork the repository.
Create a feature branch (git checkout -b feature/your-feature).
Commit changes (git commit -m 'Add your feature').
Push to the branch (git push origin feature/your-feature).
Open a pull request.

License
This project is licensed under the MIT License.
