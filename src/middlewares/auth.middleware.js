import Employee from "../models/employee.model.js";
import Admin from "../models/admin.model.js";
import { APIError } from "../utils/APIerror.js";
import { asyncHandler } from "../utils/asyncHandler.js";
import jwt from "jsonwebtoken";

export const verifyJWT = asyncHandler(async (req, res, next) => {
  try {
    const token =
      req.cookies?.accessToken ||
      req.header("Authorization")?.replace("Bearer ", "");

    if (!token) {
      throw new APIError(401, "Unauthorized request");
    }

    const decodedInfo = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);

    const admin = await Admin.findById(decodedInfo?._id).select(
      "-password -refreshToken"
    );

    if (admin) {
      req.admin = admin;
      req.userType = "admin";
      return next();
    }

    const employee = await Employee.findById(decodedInfo?._id).select(
      "-password -refreshToken"
    );

    if (employee) {
      req.employee = employee;
      req.userType = "employee";
      return next();
    }

    throw new APIError(401, "Invalid Access Token");
  } catch (error) {
    throw new APIError(401, error?.message || "Invalid Access Token");
  }
});

export const authorizeAdmin = (roles = []) => {
  return asyncHandler(async (req, res, next) => {
    if (!req.admin) {
      throw new APIError(401, "Admin authentication required");
    }

    if (roles.length && !roles.includes(req.admin.role)) {
      throw new APIError(
        403,
        `Admin with role ${req.admin.role} is not allowed to access this resource`
      );
    }

    next();
  });
};

export const isSuperAdmin = authorizeAdmin(["Super Admin"]);
export const isHRAdmin = authorizeAdmin(["HR", "Super Admin"]);
export const isAdmin = authorizeAdmin(["Admin", "HR", "Super Admin"]);