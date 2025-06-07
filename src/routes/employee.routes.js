import { Router } from "express";
import {
  applyLeave,
  deleteLeave,
  getAttendanceHistory,
  getEmployeeProfile,
  getLeaveHistory,
  loginEmployee,
  logoutEmployee,
  refreshAccessToken,
} from "../controllers/employee.controller.js";
import { verifyJWT } from "../middlewares/auth.middleware.js";
const router = Router();

// Public routes
router.route("/employee-login").post(loginEmployee);

// Protected routes
router.route("/logout").post(verifyJWT, logoutEmployee);
router.route("/refresh-token").post(refreshAccessToken);
router.route("/profile").get(verifyJWT, getEmployeeProfile);
router.route("/apply-leave").post(verifyJWT, applyLeave);
router.route("/get-leave-history").get(verifyJWT, getLeaveHistory);
router.route("/delete-leave").post(verifyJWT, deleteLeave);
router.route("/get-attendance-history").get(verifyJWT, getAttendanceHistory);

export default router;
