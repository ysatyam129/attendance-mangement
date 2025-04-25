import { asyncHandler } from "../utils/asyncHandler.js";
import { APIError } from "../utils/APIerror.js";
import { APIresponse } from "../utils/APIresponse.js";
import jwt from "jsonwebtoken";
import Employee from "../models/employee.model.js";
import LeaveModel from "../models/leave.model.js";
import AttendanceModel from "../models/attendance.model.js";

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
  const { email, password } = req.body;
  if (!email) {
    throw new APIError(400, "Employee ID or Email required");
  }

  if (!password || password.trim() === "") {
    throw new APIError(400, "Password is required");
  }

  const employee = await Employee.findOne({ email: email.toLowerCase() });

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

const getEmployeeProfile = asyncHandler(async (req, res) => {
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

    const employee = await Employee.findById({ _id: decodedToken._id }).select(
      "-password -refreshToken"
    );

    if (!employee) {
      throw new APIError(404, "Invalid credentials or employee not found");
    }

    return res.json(
      new APIresponse(200, employee, "Employee details fetched successfully")
    );
  } catch (error) {
    throw new APIError(
      400,
      `Unable to access employees details: ${error.message}`
    );
  }
});

const applyLeave = asyncHandler(async (req, res) => {
  const { _id } = req.employee;
  const { leaveType, startDate, endDate, reason } = req.body;
  if (!_id || !leaveType || !startDate || !endDate || !reason) {
    throw new APIError(400, "All fields are required");
  }

  if (new Date(startDate) > new Date(endDate)) {
    throw new APIError(400, "Start date cannot be after end date");
  }
  if (new Date(startDate) < new Date()) {
    throw new APIError(400, "Start date cannot be in the past");
  }

  const employee = await Employee.findById(_id);
  if (!employee) {
    throw new APIError(404, "Employee not found");
  }

  try {
    const leaveData = await LeaveModel.create({
      adminId: employee.adminId,
      employeeId: employee._id,
      leaveType,
      startDate,
      endDate,
      reason,
    });

    console.log(leaveData);

    return res.json(
      new APIresponse(200, leaveData, "Leave applied successfully")
    );
  } catch (error) {
    throw new APIError(
      500,
      "Something went wrong while applying leave: " + error.message
    );
  }
});

const getLeaveHistory = asyncHandler(async (req, res) => {
  const { _id } = req.body;

  try {
    const leaveHistory = await LeaveModel.aggregate([
      {
        $match: {
          employeeId: new ObjectId(`${_id}`),
        },
      },
      {
        $lookup: {
          from: "employees",
          localField: "employeeId",
          foreignField: "_id",
          as: "employee",
        },
      },
      {
        $unwind: {
          path: "$employee",
          preserveNullAndEmptyArrays: true,
        },
      },
      {
        $project: {
          employeeId: 1,
          adminId: 1,
          leaveType: 1,
          startDate: 1,
          endDate: 1,
          reason: 1,
          status: 1,
          employeeName: "$employee.fullname",
          department: "$employee.department",
          designation: "$employee.designation",
        },
      },
    ]);

    if (!leaveHistory) {
      throw new APIError(404, "No leave history found");
    }
  } catch (error) {
    throw new APIError(
      500,
      "Something went wrong while fetching leave history: " + error.message
    );
  }

  return res.json(
    new APIresponse(200, leaveHistory, "Leave history fetched successfully")
  );
});

const deleteLeave = asyncHandler(async (req, res) => {
  const { leaveId } = req.body;
  if (!leaveId) {
    throw new APIError(400, "Leave ID is required");
  }

  const leave = await LeaveModel.findById(leaveId);
  if (!leave) {
    throw new APIError(404, "Leave not found");
  }

  await LeaveModel.findByIdAndDelete(leaveId);

  return res.json(new APIresponse(200, {}, "Leave deleted successfully"));
});

const getAttendanceHistory = asyncHandler(async (req, res) => {
  const employee = await AttendanceModel.findById(req.employee._id).select(
    "-password -refreshToken"
  );

  if (!employee) {
    throw new APIError(404, "Employee not found");
  }

  return res.json(
    new APIresponse(
      200,
      employee.attendanceHistory,
      "Attendance history fetched successfully"
    )
  );
});

export {
  loginEmployee,
  logoutEmployee,
  refreshAccessToken,
  getEmployeeProfile,
  applyLeave,
  getLeaveHistory,
  deleteLeave,
  getAttendanceHistory,
};
