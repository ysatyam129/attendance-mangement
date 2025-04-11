import { asyncHandler } from "../utils/asyncHandler.js";
import { APIError } from "../utils/APIerror.js";
import Employee from "../models/employee.model.js";
import { APIresponse } from "../utils/APIresponse.js";
import jwt from "jsonwebtoken";

const generateAccessTokenAndRefreshToken = async (employeeId) => {
  try {
    const employee = await Employee.findById(employeeId);
    if (!employee) {
      throw new APIError(404, "Employee not found");
    }

    const accessToken = employee.generateAccessToken();
    const refreshToken = employee.generateRefreshToken();

    employee.refreshToken = refreshToken;
    await employee.save({ validateBeforeSave: false });

    return { accessToken, refreshToken };
  } catch (error) {
    throw new APIError(
      500,
      "Something went wrong while generating access and refresh token: " +
        error.message
    );
  }
};

const loginEmployee = asyncHandler(async (req, res) => {
  const { email, employeeId, password } = req.body;

  if (!employeeId && !email) {
    throw new APIError(400, "Employee ID or Email required");
  }

  if (employeeId && employeeId.trim() === "") {
    throw new APIError(400, "Employee ID cannot be empty");
  }

  if (!password || password.trim() === "") {
    throw new APIError(400, "Password is required");
  }

  const employee = await Employee.findOne({
    $or: [
      { employeeId: employeeId ? employeeId : "" },
      { email: email ? email.toLowerCase() : "" },
    ],
  });

  if (!employee) {
    throw new APIError(404, "Employee does not exist");
  }

  const isPasswordValid = await employee.isPasswordCorrect(password);
  if (!isPasswordValid) {
    throw new APIError(401, "Password is incorrect");
  }

  const { accessToken, refreshToken } =
    await generateAccessTokenAndRefreshToken(employee._id);

  const loggedInEmployee = await Employee.findById(employee._id).select(
    "-password -refreshToken"
  );

  const isProduction = process.env.NODE_ENV === "production";
  const options = {
    httpOnly: true,
    secure: isProduction,
    sameSite: "Strict",
  };

  return res
    .status(200)
    .cookie("accessToken", accessToken, options)
    .cookie("refreshToken", refreshToken, options)
    .json(
      new APIresponse(
        200,
        {
          employee: loggedInEmployee,
          accessToken,
          refreshToken,
        },
        "Employee logged in successfully"
      )
    );
});

const logoutEmployee = asyncHandler(async (req, res) => {
  if (!req.employee || !req.employee._id) {
    throw new APIError(
      401,
      "Unauthorized request or employee not authenticated"
    );
  }

  await Employee.findByIdAndUpdate(
    req.employee._id,
    {
      $set: {
        refreshToken: undefined,
      },
    },
    {
      new: true,
    }
  );

  const isProduction = process.env.NODE_ENV === "production";
  const options = {
    httpOnly: true,
    secure: isProduction,
    sameSite: "Strict",
  };

  return res
    .status(200)
    .clearCookie("accessToken", options)
    .clearCookie("refreshToken", options)
    .json(new APIresponse(200, {}, "Employee logged out successfully"));
});

const refreshAccessToken = asyncHandler(async (req, res) => {
  const incomingRefreshToken =
    req.cookies.refreshToken || req.body.refreshToken;

  if (!incomingRefreshToken) {
    throw new APIError(401, "Unauthorized request - Refresh token missing");
  }

  try {
    const decodedToken = jwt.verify(
      incomingRefreshToken,
      process.env.REFRESH_TOKEN_SECRET
    );

    const employee = await Employee.findById(decodedToken._id);
    if (!employee) {
      throw new APIError(401, "Invalid refresh token or employee not found");
    }

    if (incomingRefreshToken !== employee.refreshToken) {
      throw new APIError(401, "Refresh token expired or used");
    }

    const { accessToken, refreshToken } =
      await generateAccessTokenAndRefreshToken(employee._id);

    const isProduction = process.env.NODE_ENV === "production";
    const options = {
      httpOnly: true,
      secure: isProduction,
      sameSite: "Strict",
    };

    return res
      .status(200)
      .cookie("accessToken", accessToken, options)
      .cookie("refreshToken", refreshToken, options)
      .json(
        new APIresponse(
          200,
          { accessToken, refreshToken },
          "Access token refreshed successfully"
        )
      );
  } catch (error) {
    throw new APIError(401, `Invalid refresh token: ${error.message}`);
  }
});

export { loginEmployee, logoutEmployee, refreshAccessToken };
