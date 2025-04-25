import Joi from "joi";

const loginSchema = Joi.object({
    email: Joi.string()
        .email()
        .required()
        .messages({
            "string.email": "Email must be a valid email address",
            "any.required": "Email is required"
        }),
    password: Joi.string()
        .required()
        .messages({
            "any.required": "Password is required"
        })
});

const signupSchema = Joi.object({
    name: Joi.string()
        .trim()
        .min(2)
        .max(50)
        .required()
        .messages({
            "string.min": "Name must be at least 2 characters long",
            "string.max": "Name must not exceed 50 characters",
            "any.required": "Name is required"
        }),
    email: Joi.string()
        .email()
        .required()
        .messages({
            "string.email": "Email must be a valid email address",
            "any.required": "Email is required"
        }),
    password: Joi.string()
        .required()
        .messages({
            "any.required": "Password is required"
        }),
    role: Joi.string()
        .valid("user", "admin")
        .default("user")
        .messages({
            "any.only": "Role must be either 'user' or 'admin'"
        })
});

const validateBody = (schema) => {
    return (req, res, next) => {
        const { error, value } = schema.validate(req.body, { abortEarly: false });
        if (error) {
            const errorMessages = error.details.map((detail) => detail.message);
            return res.status(400).json({
                code: 400,
                message: "Validation failed",
                errors: errorMessages
            });
        }
        req.body = value;
        next();
    };
};

export const validateLogin = validateBody(loginSchema);
export const validateSignup = validateBody(signupSchema);