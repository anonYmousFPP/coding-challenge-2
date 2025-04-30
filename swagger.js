const swaggerDefinition = {
  openapi: '3.0.0',
  info: {
    title: 'User and Leave Management API',
    version: '1.0.0',
    description: 'API for user authentication, profile management, and leave applications',
  },
  servers: [
    {
      url: 'http://localhost:3000',
      description: 'Local server',
    },
  ],
  components: {
    securitySchemes: {
      BearerAuth: {
        type: 'http',
        scheme: 'bearer',
        bearerFormat: 'JWT',
      },
    },
    schemas: {
      User: {
        type: 'object',
        properties: {
          name: { type: 'string' },
          email: { type: 'string', format: 'email' },
          photoUrl: { type: 'string', format: 'uri' },
          createdAt: { type: 'string', format: 'date-time' },
        },
      },
      Leave: {
        type: 'object',
        properties: {
          leaveType: { type: 'string' },
          startDate: { type: 'string', format: 'date' },
          endDate: { type: 'string', format: 'date' },
          reason: { type: 'string' },
          status: { type: 'string', enum: ['pending', 'approved', 'rejected'] },
          user: { $ref: '#/components/schemas/User' },
          createdAt: { type: 'string', format: 'date-time' },
        },
      },
    },
  },
  paths: {
    '/users/api/v1/login': {
      post: {
        summary: 'User login',
        tags: ['Authentication'],
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: {
                type: 'object',
                properties: {
                  email: { type: 'string', format: 'email', example: 'user@example.com' },
                  password: { type: 'string', example: 'password123' },
                },
                required: ['email', 'password'],
              },
            },
          },
        },
        responses: {
          200: {
            description: 'Login successful',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    message: { type: 'string', example: 'Login Successful' },
                    token: { type: 'string', example: 'jwt_token_here' },
                  },
                },
              },
            },
          },
          400: { description: 'Incorrect password' },
          404: { description: 'User not found or missing credentials' },
          500: { description: 'Internal server error' },
        },
      },
    },
    '/users/api/v1/signup': {
      post: {
        summary: 'User signup',
        tags: ['Authentication'],
        requestBody: {
          required: true,
          content: {
            'multipart/form-data': {
              schema: {
                type: 'object',
                properties: {
                  name: { type: 'string', example: 'John Doe' },
                  email: { type: 'string', format: 'email', example: 'user@example.com' },
                  password: { type: 'string', example: 'password123' },
                  photo: { type: 'string', format: 'binary', description: 'User profile photo' },
                },
                required: ['name', 'email', 'password', 'photo'],
              },
            },
          },
        },
        responses: {
          200: {
            description: 'User created successfully',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    message: { type: 'string', example: 'User created successfully' },
                  },
                },
              },
            },
          },
          400: { description: 'Missing fields or user already exists' },
          500: { description: 'Internal server error' },
        },
      },
    },
    '/users/api/v1/forget-password': {
      post: {
        summary: 'Initiate password reset',
        tags: ['Authentication'],
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: {
                type: 'object',
                properties: {
                  email: { type: 'string', format: 'email', example: 'user@example.com' },
                },
                required: ['email'],
              },
            },
          },
        },
        responses: {
          200: {
            description: 'Password reset initiated',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    success: { type: 'boolean', example: true },
                    message: { type: 'string', example: 'Password reset initiated' },
                    resetToken: { type: 'string', example: 'reset_token_here' },
                  },
                },
              },
            },
          },
          404: {
            description: 'Email not registered',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    success: { type: 'boolean', example: false },
                    message: { type: 'string', example: 'If this email is registered, you will receive an OTP' },
                  },
                },
              },
            },
          },
          500: { description: 'Internal server error' },
        },
      },
    },
    '/users/api/v1/send-otp': {
      post: {
        summary: 'Send OTP for password reset',
        tags: ['Authentication'],
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: {
                type: 'object',
                properties: {
                  resetToken: { type: 'string', example: 'reset_token_here' },
                },
                required: ['resetToken'],
              },
            },
          },
        },
        responses: {
          200: {
            description: 'OTP sent successfully',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    success: { type: 'boolean', example: true },
                    message: { type: 'string', example: 'OTP sent to your registered email' },
                    resetToken: { type: 'string', example: 'reset_token_here' },
                  },
                },
              },
            },
          },
          400: { description: 'Invalid or expired reset token' },
          500: { description: 'Internal server error' },
        },
      },
    },
    '/users/api/v1/verify-otp': {
      post: {
        summary: 'Verify OTP and reset password',
        tags: ['Authentication'],
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: {
                type: 'object',
                properties: {
                  resetToken: { type: 'string', example: 'reset_token_here' },
                  otp: { type: 'string', example: '123456' },
                  newPassword: { type: 'string', example: 'newpassword123' },
                },
                required: ['resetToken', 'otp', 'newPassword'],
              },
            },
          },
        },
        responses: {
          200: {
            description: 'Password updated successfully',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    success: { type: 'boolean', example: true },
                    message: { type: 'string', example: 'Password updated successfully' },
                  },
                },
              },
            },
          },
          400: { description: 'Invalid OTP or token' },
          404: { description: 'User not found' },
          500: { description: 'Internal server error' },
        },
      },
    },
    '/users/api/v1/profile': {
      get: {
        summary: 'Get user profile',
        tags: ['User'],
        security: [{ BearerAuth: [] }],
        responses: {
          200: {
            description: 'Profile retrieved successfully',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    success: { type: 'boolean', example: true },
                    data: { $ref: '#/components/schemas/User' },
                  },
                },
              },
            },
          },
          401: { description: 'Unauthorized or invalid token' },
          404: { description: 'User not found' },
          500: { description: 'Internal server error' },
        },
      },
      patch: {
        summary: 'Update user profile',
        tags: ['User'],
        security: [{ BearerAuth: [] }],
        requestBody: {
          content: {
            'multipart/form-data': {
              schema: {
                type: 'object',
                properties: {
                  name: { type: 'string', example: 'Jane Doe' },
                  photo: { type: 'string', format: 'binary', description: 'New profile photo' },
                },
              },
            },
          },
        },
        responses: {
          200: {
            description: 'Profile updated successfully',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    success: { type: 'boolean', example: true },
                    message: { type: 'string', example: 'Profile updated successfully' },
                    data: {
                      type: 'object',
                      properties: {
                        name: { type: 'string', example: 'Jane Doe' },
                        photoUrl: { type: 'string', format: 'uri', example: 'https://res.cloudinary.com/.../photo.jpg' },
                      },
                    },
                  },
                },
              },
            },
          },
          401: { description: 'Unauthorized or invalid token' },
          404: { description: 'User not found' },
          500: { description: 'Internal server error' },
        },
      },
    },
    '/users/api/v1/leave': {
      post: {
        summary: 'Submit a leave application',
        tags: ['Leave'],
        security: [{ BearerAuth: [] }],
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: {
                type: 'object',
                properties: {
                  leaveType: { type: 'string', example: 'planned' },
                  startDate: { type: 'string', format: 'date', example: '2025-05-01' },
                  endDate: { type: 'string', format: 'date', example: '2025-05-05' },
                  reason: { type: 'string', example: 'Family vacation' },
                },
                required: ['leaveType', 'startDate', 'endDate', 'reason'],
              },
            },
          },
        },
        responses: {
          201: {
            description: 'Leave application submitted successfully',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    success: { type: 'boolean', example: true },
                    message: { type: 'string', example: 'Leave application submitted successfully' },
                    data: { $ref: '#/components/schemas/Leave' },
                  },
                },
              },
            },
          },
          400: { description: 'Invalid input, insufficient leaves, or overlapping leave' },
          401: { description: 'Unauthorized or invalid token' },
          404: { description: 'User not found' },
          500: { description: 'Internal server error' },
        },
      },
      get: {
        summary: 'Get leave applications',
        tags: ['Leave'],
        security: [{ BearerAuth: [] }],
        parameters: [
          {
            name: 'page',
            in: 'query',
            schema: { type: 'integer', default: 1 },
            description: 'Page number for pagination',
          },
          {
            name: 'limit',
            in: 'query',
            schema: { type: 'integer', default: 10 },
            description: 'Number of leaves per page',
          },
          {
            name: 'leaveType',
            in: 'query',
            schema: { type: 'string' },
            description: 'Filter by leave type',
          },
          {
            name: 'status',
            in: 'query',
            schema: { type: 'string', enum: ['pending', 'approved', 'rejected'] },
            description: 'Filter by leave status',
          },
        ],
        responses: {
          200: {
            description: 'Leaves retrieved successfully',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    success: { type: 'boolean', example: true },
                    data: {
                      type: 'array',
                      items: { $ref: '#/components/schemas/Leave' },
                    },
                    pagination: {
                      type: 'object',
                      properties: {
                        page: { type: 'integer', example: 1 },
                        limit: { type: 'integer', example: 10 },
                        total: { type: 'integer', example: 25 },
                        pages: { type: 'integer', example: 3 },
                      },
                    },
                  },
                },
              },
            },
          },
          401: { description: 'Unauthorized or invalid token' },
          500: { description: 'Internal server error' },
        },
      },
    },
    '/users/api/v1/leave/{leaveId}': {
      get: {
        summary: 'Get leave application details',
        tags: ['Leave'],
        security: [{ BearerAuth: [] }],
        parameters: [
          {
            name: 'leaveId',
            in: 'path',
            required: true,
            schema: { type: 'string' },
            description: 'ID of the leave application',
          },
        ],
        responses: {
          200: {
            description: 'Leave details retrieved successfully',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    success: { type: 'boolean', example: true },
                    data: { $ref: '#/components/schemas/Leave' },
                  },
                },
              },
            },
          },
          400: { description: 'Invalid leave ID' },
          401: { description: 'Unauthorized or invalid token' },
          404: { description: 'Leave not found or not authorized' },
          500: { description: 'Internal server error' },
        },
      },
    },
  },
};

const options = {
  swaggerDefinition,
  apis: [], // Add route files here if using JSDoc annotations
};

export default options;