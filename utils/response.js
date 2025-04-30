export const messages = {
    // Authentication messages
    LOGIN_SUCCESS: "Login successful",
    SIGNUP_SUCCESS: "User created successfully",
    INVALID_CREDENTIALS: "Invalid email or password",
    USER_NOT_FOUND: "User not found",
    USER_EXISTS: "User already exists with this email",
    MISSING_FIELDS: "Name, email and password are required",
    UNAUTHORIZED: "Authorization token required",
    INVALID_TOKEN: "Invalid token",
    
    // Password reset messages
    RESET_INITIATED: "Password reset initiated",
    RESET_TOKEN_INVALID: "Invalid or expired reset token",
    RESET_TOKEN_EXPIRED: "Reset token expired",
    OTP_SENT: "OTP sent to your registered email",
    OTP_INVALID: "Invalid OTP",
    OTP_EXPIRED: "OTP expired",
    PASSWORD_UPDATED: "Password updated successfully",
    
    // Profile messages
    PROFILE_RETRIEVED: "Profile retrieved successfully",
    PROFILE_UPDATED: "Profile updated successfully",
    
    // General messages
    SERVER_ERROR: "Internal server error",
    CLOUDINARY_ERROR: "Error uploading image"
};


const successResponse = (res, data = null, message = "Success", statusCode = 200) => {
    return res.status(statusCode).json({
        success: true,
        message,
        data
    });
};

const errorResponse = (res, message = "An error occurred", statusCode = 500, error = null) => {
    const response = {
        success: false,
        message
    };

    if (error && process.env.NODE_ENV === 'development') {
        response.error = error.message;
        response.stack = error.stack;
    }

    return res.status(statusCode).json(response);
};

const validationError = (res, message = "Validation failed", errors = null) => {
    const response = {
        success: false,
        message
    };

    if (errors) {
        response.errors = errors;
    }

    return res.status(400).json(response);
};

const unauthorizedResponse = (res, message = "Unauthorized") => {
    return res.status(401).json({
        success: false,
        message
    });
};

const notFoundResponse = (res, message = "Resource not found") => {
    return res.status(404).json({
        success: false,
        message
    });
};

export {
    successResponse,
    errorResponse,
    validationError,
    unauthorizedResponse,
    notFoundResponse
};