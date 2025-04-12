import { Router } from "express";
import {
  registerAdmin,
  loginAdmin,
  logoutAdmin,
  refreshAccessToken,
  getAdminProfile,
  updateAdminProfile,
  changeAdminPassword,
  registerEmployee,
  updateEmployee,
  deleteEmployee,
} from "../controllers/admin.controller.js";
import { verifyJWT } from "../middlewares/auth.middleware.js";
import { getEmployees } from "../controllers/admin.controller.js";

const router = Router();

// Public routes
router.route("/auth/register").post(registerAdmin);
router.route("/auth/login").post(loginAdmin);
router.route("/refresh-token").post(refreshAccessToken);

// Protected routes
router.route("/logout").post(verifyJWT, logoutAdmin);
router.route("/profile").get(verifyJWT, getAdminProfile);
router.route("/update-profile").patch(verifyJWT, updateAdminProfile);
router.route("/change-password").post(verifyJWT, changeAdminPassword);

// Admin privilege routes
router.route("/register-employee").post(verifyJWT, registerEmployee);
router.route("/get-employees").get(verifyJWT, getEmployees);
router.route("/update-employee").patch(verifyJWT, updateEmployee);
router.route("/delete-employee").delete(verifyJWT, deleteEmployee);

export default router;
