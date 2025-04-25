# User and Leave Management API

![Project Logo](./docs/logo.png)

This is a RESTful API built with Node.js and Express.js for user authentication, profile management, and leave application management. It supports user signup/login, password reset with OTP, profile updates with photo uploads, and leave application submission/tracking. The API is documented using Swagger (OpenAPI 3.0) and accessible at `/api-docs`.

## Table of Contents
- [Technologies Used](#technologies-used)
- [Installation](#installation)
- [Configuration](#configuration)
- [Running the Application](#running-the-application)
- [Swagger Documentation](#swagger-documentation)
- [Swagger Screenshots](#swagger-screenshots)
- [Project Structure](#project-structure)
- [API Endpoints](#api-endpoints)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [License](#license)

## Technologies Used

- **Node.js**: JavaScript runtime for server-side development.
- **Express.js**: Web framework for building RESTful APIs.
- **MongoDB**: NoSQL database for storing user and leave data.
- **Mongoose**: ODM for MongoDB to manage schemas and queries.
- **jsonwebtoken**: Secure user authentication with JWT tokens.
- **bcrypt**: Password hashing for secure storage.
- **nodemailer**: Sending OTP emails for password reset.
- **cloudinary**: Uploading and managing user profile photos.
- **express-fileupload**: Handling file uploads.
- **morgan**: HTTP request logging.
- **winston & winston-daily-rotate-file**: Advanced logging with daily rotation.
- **swagger-ui-express & swagger-jsdoc**: API documentation and interactive UI.
- **dotenv**: Managing environment variables.
- **crypto**: Generating OTPs and reset tokens.

## Installation

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/anonYmousFPP/coding-challenge-2.git
   cd coding-challenge-2
   ```

2. **Install Dependencies**:
   Ensure Node.js (v16 or higher) is installed, then install all required packages:
   ```bash
   npm install
   ```

   Installed packages:
   - `express`
   - `mongoose`
   - `express-fileupload`
   - `morgan`
   - `winston`
   - `winston-daily-rotate-file`
   - `jsonwebtoken`
   - `bcrypt`
   - `nodemailer`
   - `cloudinary`
   - `dotenv`
   - `swagger-ui-express`
   - `swagger-jsdoc`

## Configuration

1. **Create a `.env` File**:
   In the project root, create a `.env` file with the following:
   ```env
   MONGO_URL=your_mongodb_connection_string
   PORT=3000
   JWT_SECRET=your_jwt_secret
   CLOUDINARY_CLOUD_NAME=your_cloudinary_cloud_name
   CLOUDINARY_API_KEY=your_cloudinary_api_key
   CLOUDINARY_API_SECRET=your_cloudinary_api_secret
   EMAIL_USERNAME=your_email_username
   EMAIL_PASSWORD=your_email_password
   ```

   - `MONGO_URL`: MongoDB connection string (e.g., `mongodb://localhost:27017/your_database` or MongoDB Atlas URI).
   - `PORT`: Server port (default: 3000).
   - `JWT_SECRET`: Random string for JWT signing.
   - `CLOUDINARY_*`: Credentials from [Cloudinary](https://cloudinary.com).
   - `EMAIL_USERNAME/PASSWORD`: Gmail credentials or app-specific password (enable 2FA and generate an app password for Gmail).

2. **Create Logs Directory**:
   ```bash
   mkdir logs
   ```

3. **Create Docs Directory**:
   For logo and screenshots:
   ```bash
   mkdir docs
   ```

## Running the Application

1. **Start the Server**:
   ```bash
   npm start
   ```
   This runs `node index.js`, starting the server on the port specified in `.env` (default: 3000).

2. **Access the API**:
   - **Base URL**: `http://localhost:3000/users/api/v1`
   - **Swagger UI**: `http://localhost:3000/api-docs`

3. **Test Endpoints**:
   Use Postman, cURL, or Swagger UI. Start with `POST /users/api/v1/login` to get a JWT token, then use it for authenticated routes.

## Swagger Documentation

The API is documented using Swagger (OpenAPI 3.0). Access the interactive Swagger UI at:
```
http://localhost:3000/api-docs
```

The Swagger UI provides:
- **Authentication Endpoints**: Login, signup, password reset (forget-password, send-otp, verify-otp).
- **User Endpoints**: Get and update user profile.
- **Leave Endpoints**: Submit, list, and view leave applications.

## Swagger Screenshots

Below are screenshots of the Swagger UI showcasing the API documentation:

1. **Swagger UI Overview**:
   ![Swagger Overview](./docs/swagger-overview.png)
   _Shows the main Swagger UI with all endpoint categories._

2. **Authentication Endpoints**:
   ![Authentication Endpoints](./docs/swagger-auth.png)
   _Displays the authentication endpoints like login and signup._

3. **Leave Endpoints**:
   ![Leave Endpoints](./docs/swagger-leave.png)
   _Highlights the leave management endpoints._

**To Add Screenshots**:
1. Run the application (`npm start`).
2. Open `http://localhost:3000/api-docs` in your browser.
3. Take screenshots:
   - Overview: Full Swagger UI with all sections visible.
   - Authentication: Expanded authentication endpoints.
   - Leave: Expanded leave endpoints.
4. Save them as:
   - `docs/swagger-overview.png`
   - `docs/swagger-auth.png`
   - `docs/swagger-leave.png`
5. Ensure the paths in the `README.md` are correct.

## Project Structure

```
project-root/
├── database/                   # Mongoose schemas
│   ├── user.schema.js
│   ├── leave.schema.js
├── routes/                     # API route handlers
│   ├── auth.route.js
│   ├── leave.routes.js
├── utils/                      # Utility modules
│   ├── logger.js
├── middleware/                 # Custom middleware
│   ├── user.middleware.js
├── validators/                 # Request validation
│   ├── auth.validators.js
├── logs/                       # Log files
│   ├── application-*.log
│   ├── exceptions-*.log
├── docs/                       # Documentation assets
│   ├── logo.png
│   ├── swagger-overview.png
│   ├── swagger-auth.png
│   ├── swagger-leave.png
├── .env                        # Environment variables
├── index.js                    # Main application file
├── swagger.js                  # Swagger configuration
├── package.json
└── node_modules/
```

## API Endpoints

### Authentication
- **POST /users/api/v1/login**: Authenticate a user and return a JWT token.
- **POST /users/api/v1/signup**: Register a new user with a profile photo.
- **POST /users/api/v1/forget-password**: Initiate password reset and get a reset token.
- **POST /users/api/v1/send-otp**: Send OTP to the user’s email for password reset.
- **POST /users/api/v1/verify-otp**: Verify OTP and update the password.

### User
- **GET /users/api/v1/profile**: Retrieve the authenticated user’s profile (requires JWT).
- **PATCH /users/api/v1/profile**: Update the user’s name or photo (requires JWT).

### Leave
- **POST /users/api/v1/leave**: Submit a leave application (requires JWT).
- **GET /users/api/v1/leave**: List leave applications with pagination and filters (requires JWT).
- **GET /users/api/v1/leave/{leaveId}**: Get details of a specific leave application (requires JWT).

Explore all endpoints in the Swagger UI for detailed request/response schemas.

## Troubleshooting

- **Swagger UI Not Loading**:
  - Ensure `swagger-ui-express` and `swagger-jsdoc` are installed (`npm install swagger-ui-express swagger-jsdoc`).
  - Check `swagger.js` for syntax errors.
  - Verify the server is running and access `http://localhost:3000/api-docs`.

- **MongoDB Connection Errors**:
  - Confirm `MONGO_URL` in `.env` is correct and MongoDB is running.
  - For MongoDB Atlas, ensure your IP is whitelisted.

- **Cloudinary Upload Fails**:
  - Verify `CLOUDINARY_CLOUD_NAME`, `CLOUDINARY_API_KEY`, and `CLOUDINARY_API_SECRET` in `.env`.
  - Check network connectivity and Cloudinary account status.

- **Nodemailer Email Issues**:
  - Ensure `EMAIL_USERNAME` and `EMAIL_PASSWORD` are correct.
  - For Gmail, enable 2FA and use an app-specific password.

- **Logs Not Generating**:
  - Ensure the `logs/` directory exists (`mkdir logs`).
  - Check `logger.js` for configuration issues.

- **General Errors**:
  - Review logs in `logs/application-*.log` and `logs/exceptions-*.log`.
  - Run `npm install` to ensure all dependencies are installed.

## Contributing

Contributions are welcome! Please:
1. Fork the repository.
2. Create a feature branch (`git checkout -b feature/your-feature`).
3. Commit changes (`git commit -m 'Add your feature'`).
4. Push to the branch (`git push origin feature/your-feature`).
5. Open a pull request.

## License

This project is licensed under the MIT License.