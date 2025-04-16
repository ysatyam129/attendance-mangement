import { Router } from "express";
import { getEmployeeProfile, loginEmployee, logoutEmployee, refreshAccessToken } from "../controllers/employee.controller.js";
import { verifyJWT } from "../middlewares/auth.middleware.js";
const router = Router();

// Public routes
router.route("/employee-login").post(loginEmployee);

// Protected routes
router.route("/logout").post(verifyJWT, logoutEmployee);
router.route("/refresh-token").post(refreshAccessToken);
router.route("/profile").get(verifyJWT, getEmployeeProfile);

export default router;
