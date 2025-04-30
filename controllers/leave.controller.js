import jwt from "jsonwebtoken";
import mongoose from "mongoose";
import User from "../database/user.schema.js";
import Leave from "../database/leave.schema.js";
import logger from "../utils/logger.js";
import {
    successResponse,
    errorResponse,
    validationError,
    unauthorizedResponse,
    notFoundResponse,
    messages
} from "../utils/response.js";

const isBackdated = (date) => {
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    const threeDaysAgo = new Date(today);
    threeDaysAgo.setDate(today.getDate() - 3);
    return date < threeDaysAgo;
};

export const createLeave = async (req, res) => {
    try {
        const token = req.headers.authorization?.split(" ")[1];
        if (!token) {
            logger.warn('Unauthorized leave request attempt - missing token');
            return unauthorizedResponse(res, messages.UNAUTHORIZED);
        }

        logger.debug('Leave request received', { headers: req.headers, body: req.body });

        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const userId = decoded.userId;

        const { leaveType, startDate, endDate, reason } = req.body;

        if (!leaveType || !startDate || !endDate || !reason) {
            logger.warn('Missing required fields in leave request', { body: req.body });
            return validationError(res, messages.MISSING_FIELDS);
        }

        const start = new Date(startDate);
        const end = new Date(endDate);
        start.setHours(0, 0, 0, 0);
        end.setHours(0, 0, 0, 0);

        if (isBackdated(start)) {
            return validationError(res, "Backdated leave applications older than 3 days are not allowed");
        }

        if (end < start) {
            return validationError(res, "End date cannot be before start date");
        }

        const user = await User.findById(userId);
        if (!user) {
            return notFoundResponse(res, messages.USER_NOT_FOUND);
        }

        const existingLeave = await Leave.findOne({
            user: userId,
            $or: [
                { startDate: { $lte: end }, endDate: { $gte: start } }
            ]
        });

        if (existingLeave) {
            return validationError(res, "You already have a leave application for this period");
        }

        const timeDiff = end - start;
        const leaveDays = Math.ceil(timeDiff / (1000 * 60 * 60 * 24)) + 1;

        if (user.leavesUsed + leaveDays > user.totalLeaves) {
            return validationError(res, `You don't have enough leaves. Available: ${user.totalLeaves - user.leavesUsed}`);
        }

        const leave = new Leave({
            user: userId,
            leaveType,
            startDate: start,
            endDate: end,
            reason,
            status: "pending"
        });

        await leave.save();

        logger.info(`Leave application submitted by user ${userId}`, {
            leaveType,
            startDate,
            endDate,
            leaveDays
        });

        return successResponse(res, leave, "Leave application submitted successfully", 201);

    } catch (error) {
        logger.error('Leave application error:', error);
        if (error instanceof jwt.JsonWebTokenError) {
            return unauthorizedResponse(res, messages.INVALID_TOKEN);
        }
        return errorResponse(res, messages.SERVER_ERROR, 500, error);
    }
};

export const getLeaves = async (req, res) => {
    try {
        const token = req.headers.authorization?.split(" ")[1];
        if (!token) {
            logger.warn('Unauthorized leave list request - missing token');
            return unauthorizedResponse(res, messages.UNAUTHORIZED);
        }

        logger.debug('Leave list request received', {
            query: req.query,
            headers: req.headers
        });

        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const userId = decoded.userId;

        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 10;
        const skip = (page - 1) * limit;

        const filter = { user: userId };
        if (req.query.leaveType) {
            filter.leaveType = req.query.leaveType;
        }
        if (req.query.status) {
            filter.status = req.query.status;
        }

        const leaves = await Leave.find(filter)
            .sort({ createdAt: -1 })
            .skip(skip)
            .limit(limit)
            .populate('user', 'name email');

        const total = await Leave.countDocuments(filter);

        logger.info('Leave list retrieved successfully', {
            userId,
            page,
            limit,
            total
        });

        return successResponse(res, {
            data: leaves,
            pagination: {
                page,
                limit,
                total,
                pages: Math.ceil(total / limit)
            }
        });

    } catch (error) {
        logger.error('Failed to retrieve leave list', error);
        if (error instanceof jwt.JsonWebTokenError) {
            return unauthorizedResponse(res, messages.INVALID_TOKEN);
        }
        return errorResponse(res, messages.SERVER_ERROR, 500, error);
    }
};

export const getLeaveById = async (req, res) => {
    try {
        const token = req.headers.authorization?.split(" ")[1];
        if (!token) {
            logger.warn('Unauthorized leave details request - missing token');
            return unauthorizedResponse(res, messages.UNAUTHORIZED);
        }

        logger.debug('Leave details request received', {
            params: req.params,
            headers: req.headers
        });

        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const userId = decoded.userId;

        const leaveId = req.params.leaveId;
        if (!mongoose.Types.ObjectId.isValid(leaveId)) {
            return validationError(res, "Invalid leave ID");
        }

        const leave = await Leave.findOne({
            _id: leaveId,
            user: userId
        }).populate('user', 'name email');

        if (!leave) {
            return notFoundResponse(res, "Leave not found or not authorized");
        }

        logger.info('Leave details retrieved successfully', {
            userId,
            leaveId
        });
        return successResponse(res, leave);

    } catch (error) {
        logger.error('Failed to retrieve leave details', error);
        if (error instanceof jwt.JsonWebTokenError) {
            return unauthorizedResponse(res, messages.INVALID_TOKEN);
        }
        return errorResponse(res, messages.SERVER_ERROR, 500, error);
    }
};