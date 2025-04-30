import { Router } from "express";
import {
    createLeave,
    getLeaves,
    getLeaveById
} from "../controllers/leave.controller.js";

const route = Router();

route.post('/', createLeave);
route.get('/', getLeaves);
route.get('/:leaveId', getLeaveById);

export default route;