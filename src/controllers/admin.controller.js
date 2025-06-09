import jwt from "jsonwebtoken";
import { ObjectId } from "mongodb";

import { asyncHandler } from "../utils/asyncHandler.js";
import { APIError } from "../utils/APIerror.js";
import { APIresponse } from "../utils/APIresponse.js";
import { EMPLOYEE_TYPES, ADMIN_ROLES, EMPLOYEE_SHIFT } from "../constants.js";

import Admin from "../models/admin.model.js";
import EmployeeModel from "../models/employee.model.js";
import AttendanceModel from "../models/attendance.model.js";
import LeaveModel from "../models/leave.model.js";

const isValidEmail = (email) => {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
};

const isValidPhone = (phone) => {
  const phoneRegex = /^\d{10}$/;
  return phoneRegex.test(phone.toString());
};

const isStrongPassword = (password) => {
  const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,}$/;
  return passwordRegex.test(password);
};

const validateShiftDetails = (shift) => {
  return EMPLOYEE_SHIFT.includes(shift);
};

const isValidDate = (date) => {
  return !isNaN(new Date(date).getTime());
};

const generateAccessTokenAndRefreshToken = async (adminId) => {
  try {
    const admin = await Admin.findById(adminId);
    if (!admin) {
      throw new APIError(404, "Admin not found");
    }

    const accessToken = admin.generateAccessToken();
    const refreshToken = admin.generateRefreshToken();

    admin.refreshToken = refreshToken;
    await admin.save({ validateBeforeSave: false });

    return { accessToken, refreshToken };
  } catch (error) {
    throw new APIError(
      500,
      "Something went wrong while generating access and refresh token: " +
      error.message
    );
  }
};

const registerAdmin = asyncHandler(async (req, res) => {
  const { name, email, phone, role, password } = req.body;
  console.log("This is the body of the request", req.body);
  if (!name || !email || !phone || !role || !password) {
    throw new APIError(400, "All required fields must be provided");
  }

  if ([name, email, role, password].some((field) => field.trim() === "")) {
    throw new APIError(400, "No empty field is allowed");
  }

  if (!isValidEmail(email)) {
    throw new APIError(400, "Invalid email format");
  }

  if (!isValidPhone(phone)) {
    throw new APIError(400, "Invalid phone number. Must be 10 digits");
  }

  if (!ADMIN_ROLES.includes(role)) {
    throw new APIError(
      400,
      `Invalid admin role. Must be one of: ${ADMIN_ROLES.join(", ")}`
    );
  }

  if (!isStrongPassword(password)) {
    throw new APIError(
      400,
      "Password must be at least 8 characters long and include uppercase, lowercase, and numbers"
    );
  }

  const existedAdmin = await Admin.findOne({ email: email.toLowerCase() });

  if (existedAdmin) {
    throw new APIError(409, "Admin with this username or email already exists");
  }

  try {
    const admin = await Admin.create({
      name,
      email: email.toLowerCase(),
      phone,
      role,
      password,
    });

    const createdAdmin = await Admin.findById(admin._id).select(
      "-password -refreshToken"
    );

    if (!createdAdmin) {
      throw new APIError(
        500,
        "Something went wrong while registering the Admin"
      );
    }

    return res
      .status(201)
      .json(
        new APIresponse(201, createdAdmin, "Admin registered successfully")
      );
  } catch (error) {
    throw new APIError(500, `Failed to register admin: ${error.message}`);
  }
});

const loginAdmin = asyncHandler(async (req, res) => {
  const { email, password } = req.body;

  if (!email) {
    throw new APIError(400, "Username or Email required");
  }

  if (email && !isValidEmail(email)) {
    throw new APIError(400, "Invalid email format");
  }

  if (!password || password.trim() === "") {
    throw new APIError(400, "Password is required");
  }

  const admin = await Admin.findOne({ email: email.toLowerCase() });

  if (!admin) {
    throw new APIError(404, "Admin does not exist");
  }

  const isPasswordValid = await admin.isPasswordCorrect(password);
  if (!isPasswordValid) {
    throw new APIError(401, "Password is incorrect");
  }

  const { accessToken, refreshToken } =
    await generateAccessTokenAndRefreshToken(admin._id);

  const loggedInAdmin = await Admin.findById(admin._id).select(
    "-password -refreshToken"
  );

  const options = {
    httpOnly: true,
    secure: true,
  };

  return res
    .status(200)
    .cookie("accessToken", accessToken, options)
    .cookie("refreshToken", refreshToken, options)
    .json(
      new APIresponse(
        200,
        {
          admin: loggedInAdmin,
          accessToken,
          refreshToken,
        },
        "Admin logged in successfully"
      )
    );
});

const logoutAdmin = asyncHandler(async (req, res) => {
  if (!req.admin || !req.admin._id) {
    throw new APIError(401, "Unauthorized request or admin not authenticated");
  }

  try {
    await Admin.findByIdAndUpdate(
      req.admin._id,
      {
        $set: {
          refreshToken: undefined,
        },
      },
      {
        new: true,
      }
    );

    const options = {
      httpOnly: true,
      secure: true,
    };

    return res
      .status(200)
      .clearCookie("accessToken", options)
      .clearCookie("refreshToken", options)
      .json(new APIresponse(200, {}, "Admin logged out successfully"));
  } catch (error) {
    throw new APIError(500, `Error during logout: ${error.message}`);
  }
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

    const admin = await Admin.findById(decodedToken._id);
    if (!admin) {
      throw new APIError(401, "Invalid refresh token or admin not found");
    }

    if (incomingRefreshToken !== admin.refreshToken) {
      throw new APIError(401, "Refresh token expired or used");
    }

    const { accessToken, refreshToken } =
      await generateAccessTokenAndRefreshToken(admin._id);

    const options = {
      httpOnly: true,
      secure: true,
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

const getAdminProfile = asyncHandler(async (req, res) => {
  if (!req.admin || !req.admin._id) {
    throw new APIError(401, "Unauthorized request");
  }

  const admin = await Admin.findById(req.admin._id).select(
    "-password -refreshToken"
  );

  if (!admin) {
    throw new APIError(404, "Admin profile not found");
  }

  return res
    .status(200)
    .json(new APIresponse(200, admin, "Admin profile fetched successfully"));
});

const updateAdminProfile = asyncHandler(async (req, res) => {
  if (!req.admin || !req.admin._id) {
    throw new APIError(401, "Unauthorized request");
  }

  const { username, phone } = req.body;

  const updatableFields = {};

  if (username && username.trim() !== "") {
    const existingAdmin = await Admin.findOne({
      username,
      _id: { $ne: req.admin._id },
    });

    if (existingAdmin) {
      throw new APIError(409, "Username already taken");
    }

    updatableFields.username = username;
  }

  if (phone) {
    if (!isValidPhone(phone)) {
      throw new APIError(400, "Invalid phone number. Must be 10 digits");
    }
    updatableFields.phone = phone;
  }

  if (Object.keys(updatableFields).length === 0) {
    throw new APIError(400, "No valid fields provided for update");
  }

  const updatedAdmin = await Admin.findByIdAndUpdate(
    req.admin._id,
    {
      $set: updatableFields,
    },
    {
      new: true,
    }
  ).select("-password -refreshToken");

  if (!updatedAdmin) {
    throw new APIError(500, "Failed to update admin profile");
  }

  return res
    .status(200)
    .json(
      new APIresponse(200, updatedAdmin, "Admin profile updated successfully")
    );
});

const changeAdminPassword = asyncHandler(async (req, res) => {
  if (!req.admin || !req.admin._id) {
    throw new APIError(401, "Unauthorized request");
  }

  const { currentPassword, newPassword } = req.body;

  if (!currentPassword || !newPassword) {
    throw new APIError(400, "Current password and new password are required");
  }

  const admin = await Admin.findById(req.admin._id);

  if (!admin) {
    throw new APIError(404, "Admin not found");
  }

  const isPasswordCorrect = await admin.isPasswordCorrect(currentPassword);

  if (!isPasswordCorrect) {
    throw new APIError(401, "Current password is incorrect");
  }

  if (!isStrongPassword(newPassword)) {
    throw new APIError(
      400,
      "New password must be at least 8 characters long and include uppercase, lowercase, and numbers"
    );
  }

  admin.password = newPassword;

  await admin.save({ validateBeforeSave: true });

  return res
    .status(200)
    .json(new APIresponse(200, {}, "Admin password changed successfully"));
});

const registerEmployee = asyncHandler(async (req, res) => {
  const {
    employeeId,
    fullname,
    email,
    phone,
    designation,
    department,
    joiningDate,
    employeeType,
    shiftDetails,
  } = req.body;

  const admin = req.admin;
  const password = email.split("@")[0];

  if (
    !employeeId ||
    !fullname ||
    !email ||
    !phone ||
    !designation ||
    !department ||
    !employeeType ||
    !password ||
    !shiftDetails
  ) {
    throw new APIError(400, "All required fields must be provided");
  }

  if (
    [
      employeeId,
      fullname,
      email,
      designation,
      department,
      employeeType,
      password,
      shiftDetails,
    ].some((field) => field.trim() === "")
  ) {
    throw new APIError(400, "No empty field is allowed");
  }

  if (!isValidEmail(email)) {
    throw new APIError(400, "Invalid email format");
  }

  if (!isValidPhone(phone)) {
    throw new APIError(400, "Invalid phone number. Must be 10 digits");
  }

  if (!EMPLOYEE_TYPES.includes(employeeType)) {
    throw new APIError(
      400,
      `Invalid employee type. Must be one of: ${EMPLOYEE_TYPES.join(", ")}`
    );
  }

  // if (!isStrongPassword(password)) {
  //   throw new APIError(
  //     400,
  //     "Password must be at least 8 characters long and include uppercase, lowercase, and numbers"
  //   );
  // }

  if (joiningDate && !isValidDate(joiningDate)) {
    throw new APIError(400, "Invalid joining date format");
  }

  if (shiftDetails && !validateShiftDetails(shiftDetails)) {
    throw new APIError(400, "Invalid shift details format or values");
  }

  const existedEmployee = await EmployeeModel.findOne({
    $or: [{ employeeId }, { email }],
  });

  if (existedEmployee) {
    throw new APIError(409, "Employee with this ID or Email already exists");
  }

  const formattedJoiningDate = joiningDate ? new Date(joiningDate) : new Date();

  try {
    const employee = await EmployeeModel.create({
      employeeId,
      fullname: fullname.toLowerCase(),
      email: email.toLowerCase(),
      phone,
      designation,
      department,
      joiningDate: formattedJoiningDate,
      employeeType,
      shiftDetails,
      password,
      adminId: admin._id,
    });

    const createdEmployee = await EmployeeModel.findById(employee._id).select(
      "-password -refreshToken"
    );

    if (!createdEmployee) {
      throw new APIError(
        500,
        "Something went wrong while registering the Employee"
      );
    }

    return res
      .status(201)
      .json(
        new APIresponse(
          201,
          createdEmployee,
          "Employee registered successfully"
        )
      );
  } catch (error) {
    throw new APIError(500, `Failed to register employee: ${error.message}`);
  }
});

const getEmployees = asyncHandler(async (req, res) => {
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

    const employees = await EmployeeModel.find({ adminId: decodedToken._id })
      .select("-password -refreshToken")
      .sort({ createdAt: -1 });

    if (!employees) {
      throw new APIError(404, "No employees found for this admin");
    }

    return res
      .status(200)
      .json(new APIresponse(200, employees, "Employees fetched successfully"));
  } catch (error) {
    throw new APIError(
      400,
      `Unable to access employees details: ${error.message}`
    );
  }
});

const updateEmployee = asyncHandler(async (req, res) => {
  console.log("This is the body of the request", req.body);
  // const employeeId = req.params.employeeId;
  const {
    employeeId,
    fullname,
    email,
    phone,
    designation,
    joiningDate,
    employeeType,
    shiftDetails,
  } = req.body;

  const admin = req.admin;

  if (!employeeId) {
    throw new APIError(400, "Employee ID is required");
  }

  const employee = await EmployeeModel.findById(employeeId);

  if (!employee) {
    throw new APIError(404, "Employee not found");
  }

  if (employee.adminId.toString() !== admin._id.toString()) {
    throw new APIError(
      403,
      "You don't have permission to update this employee"
    );
  }

  if (email && !isValidEmail(email)) {
    throw new APIError(400, "Invalid email format");
  }

  if (phone && !isValidPhone(phone)) {
    throw new APIError(400, "Invalid phone number. Must be 10 digits");
  }

  if (employeeType && !EMPLOYEE_TYPES.includes(employeeType)) {
    throw new APIError(
      400,
      `Invalid employee type. Must be one of: ${EMPLOYEE_TYPES.join(", ")}`
    );
  }

  if (joiningDate && !isValidDate(joiningDate)) {
    throw new APIError(400, "Invalid joining date format");
  }

  if (shiftDetails && !validateShiftDetails(shiftDetails)) {
    throw new APIError(400, "Invalid shift details format or values");
  }

  if (email || employeeId) {
    const existingEmployee = await EmployeeModel.findOne({
      $and: [
        { _id: { $ne: employeeId } },
        {
          $or: [
            ...(email ? [{ email: email.toLowerCase() }] : []),
            ...(employeeId ? [{ employeeId }] : []),
          ],
        },
      ],
    });

    if (existingEmployee) {
      throw new APIError(409, "Employee with this ID or Email already exists");
    }
  }

  const updateData = {};

  // if (employeeId) updateData.employeeId = employeeId;
  if (fullname) updateData.fullname = fullname.toLowerCase();
  if (email) updateData.email = email.toLowerCase();
  if (phone) updateData.phone = phone;
  if (designation) updateData.designation = designation;
  if (joiningDate) updateData.joiningDate = new Date(joiningDate);
  if (employeeType) updateData.employeeType = employeeType;
  if (shiftDetails) updateData.shiftDetails = shiftDetails;

  try {
    const updatedEmployee = await EmployeeModel.findByIdAndUpdate(
      employeeId,
      { $set: updateData },
      { new: true }
    ).select("-password -refreshToken");

    if (!updatedEmployee) {
      throw new APIError(
        500,
        "Something went wrong while updating the employee"
      );
    }

    return res
      .status(200)
      .json(
        new APIresponse(200, updatedEmployee, "Employee updated successfully")
      );
  } catch (error) {
    throw new APIError(500, `Failed to update employee: ${error.message}`);
  }
});

const deleteEmployee = asyncHandler(async (req, res) => {
  const { employeeId } = req.body;
  const admin = req.admin;
  if (!employeeId) {
    throw new APIError(400, "Employee ID is required");
  }

  // Find employee by employeeId field instead of _id
  const employee = await EmployeeModel.findOne({ employeeId: employeeId });

  if (!employee) {
    throw new APIError(404, "Employee not found");
  }

  if (employee.adminId.toString() !== admin._id.toString()) {
    throw new APIError(
      403,
      "You don't have permission to delete this employee"
    );
  }

  try {
    // Delete employee by employeeId field
    const deletedEmployee = await EmployeeModel.findOneAndDelete({
      employeeId: employeeId,
    });

    if (!deletedEmployee) {
      throw new APIError(
        500,
        "Something went wrong while deleting the employee"
      );
    }

    return res
      .status(200)
      .json(
        new APIresponse(
          200,
          { employeeId: deletedEmployee.employeeId },
          "Employee deleted successfully"
        )
      );
  } catch (error) {
    throw new APIError(500, `Failed to delete employee: ${error.message}`);
  }
});

const getEmployeeDetails = asyncHandler(async (req, res) => {
  const admin = req.admin;

  try {
    const employees = await EmployeeModel.find({ adminId: admin._id }).select(
      "_id employeeId adminId fullname designation department employeeType shiftDetails attendanceStatus"
    );

    if (!employees || employees.length === 0) {
      throw new APIError(404, "No employees found for this admin");
    }

    const today = new Date();
    const startOfDay = new Date(today.setHours(0, 0, 0, 0));
    const endOfDay = new Date(today.setHours(23, 59, 59, 999));

    const attendanceRecords = await AttendanceModel.find({
      employeeId: { $in: employees.map((emp) => emp._id) },
      date: { $gte: startOfDay, $lte: endOfDay },
    }).select("-createdAt -updatedAt -__v");

    const employeesWithAttendance = employees.map((employee) => {
      const todayAttendance = attendanceRecords.find(
        (record) => record.employeeId.toString() === employee._id.toString()
      );
      if (todayAttendance) {
        const employeeObj = employee.toObject();
        const attendanceObj = todayAttendance.toObject();
        return {
          ...employeeObj,
          adminId: attendanceObj.adminId,
          attendanceStatus: attendanceObj.attendanceStatus,
          date: attendanceObj.date,
          remarks: attendanceObj.remarks,
        };
      } else {
        return employee.toObject();
      }
    });

    return res
      .status(200)
      .json(
        new APIresponse(
          200,
          { employees: employeesWithAttendance },
          "Employees fetched successfully"
        )
      );
  } catch (error) {
    throw new APIError(
      400,
      `Unable to access employees details: ${error.message}`
    );
  }
});

const markAttendance = asyncHandler(async (req, res) => {
  const { date, records } = req.body.attendanceData;
  const admin = req.admin;

  if (!date || !records || (Array.isArray(records) && records.length === 0)) {
    throw new APIError(
      400,
      "No employees or date provided for attendance marking"
    );
  }

  const recordsArray = Array.isArray(records) ? records : [records];

  try {
    // Fetch IDs of employees that belong to this admin
    const adminEmployees = await EmployeeModel.find({ adminId: admin._id })
      .select("_id")
      .lean();

    // Set of valid employee IDs
    const employeeSet = new Set(
      adminEmployees.map((emp) => emp._id.toString())
    );

    const allRecords = [];
    const invalidEmployees = [];

    for (const record of recordsArray) {
      const { employeeId, attendanceStatus, remarks } = record;

      if (!employeeId || !attendanceStatus) {
        throw new APIError(
          400,
          "Employee ID and attendanceStatus are required"
        );
      }

      // Check if this employee belongs to the admin
      if (employeeSet.has(employeeId.toString())) {
        allRecords.push({
          adminId: admin._id,
          employeeId,
          attendanceStatus,
          date: date ? new Date(date) : new Date(),
          remarks: remarks || "",
        });
      } else {
        invalidEmployees.push(employeeId);
      }
    }

    if (allRecords.length === 0) {
      throw new APIError(
        400,
        "None of the provided employees belong to this admin"
      );
    }

    const attendanceRecords = await AttendanceModel.insertMany(allRecords);

    if (!attendanceRecords) {
      throw new APIError(500, "Something went wrong while marking attendance");
    }

    // Include information about skipped employees in the response
    const responseMessage =
      invalidEmployees.length > 0
        ? `Attendance marked successfully. Skipped ${invalidEmployees.length} employees that don't belong to this admin.`
        : "Attendance marked successfully";

    return res.status(200).json(
      new APIresponse(
        200,
        {
          attendanceRecords,
          skippedEmployees: invalidEmployees,
        },
        responseMessage
      )
    );
  } catch (error) {
    throw new APIError(500, `Failed to mark attendance: ${error.message}`);
  }
});

const getHistory = asyncHandler(async (req, res) => {
  const admin = req.admin;
  const { dateRange } = req.body;

  let startDate, endDate;

  if (!dateRange) {
    startDate = new Date().toISOString().split("T")[0];
    endDate = null;
  } else {
    startDate = dateRange.startDate;
    endDate = dateRange.endDate;

    if (!isValidDate(startDate) || (endDate && !isValidDate(endDate))) {
      throw new APIError(400, "Invalid date range provided");
    }
  }

  try {
    const dateQuery = { $lte: new Date(startDate) };

    if (endDate) {
      dateQuery.$gte = new Date(endDate);
    }

    const attendanceRecords = await AttendanceModel.aggregate([
      {
        $match: {
          adminId: new ObjectId(`${admin._id}`),
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
          _id: 1,
          date: 1,
          attendanceStatus: 1,
          employeeId: "$employee.employeeId",
          remarks: 1,
          fullname: "$employee.fullname",
          department: "$employee.department",
          designation: "$employee.designation",
        },
      },
      {
        $sort: {
          date: -1,
        },
      },
    ]);

    if (!attendanceRecords || attendanceRecords.length === 0) {
      throw new APIError(404, "No attendance records found");
    }

    const groupedByDate = {};

    attendanceRecords.forEach((record) => {
      const dateString = record.date.toISOString().split("T")[0];

      if (!groupedByDate[dateString]) {
        groupedByDate[dateString] = [];
      }

      groupedByDate[dateString].push({
        _id: record._id,
        employeeId: record.employeeId,
        attendanceStatus: record.attendanceStatus,
        remarks: record.remarks || null,
        fullname: record.fullname,
        department: record.department,
        designation: record.designation,
      });
    });

    const formattedRecords = Object.keys(groupedByDate).map((date) => {
      return {
        date: date,
        records: groupedByDate[date],
      };
    });

    return res
      .status(200)
      .json(
        new APIresponse(
          200,
          formattedRecords,
          "Attendance history fetched successfully"
        )
      );
  } catch (error) {
    throw new APIError(
      500,
      `Failed to fetch attendance history: ${error.message}`
    );
  }
});

const getLeaveDetails = asyncHandler(async (req, res) => {
  const admin = req.admin;

  try {
    const leaveRecords = await LeaveModel.aggregate([
      {
        $match: {
          adminId: new ObjectId(`${admin._id}`),
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
          _id: 1,
          adminId: 1,
          employeeName: "$employee.fullname",
          employeeId: "$employee.employeeId",
          department: "$employee.department",
          leaveType: 1,
          reason: 1,
          status: 1,
          startDate: 1,
          endDate: 1,
          rejectedReason: 1,
          submittedAt: "$createdAt",
        },
      },
      {
        $sort: {
          date: -1,
        },
      },
    ]);
    if (!leaveRecords || leaveRecords.length === 0) {
      throw new APIError(404, "No leave records found");
    }

    return res
      .status(200)
      .json(
        new APIresponse(200, leaveRecords, "Leave records fetched successfully")
      );
  } catch (error) {
    throw new APIError(500, `Failed to fetch leave details: ${error.message}`);
  }
});

const setLeaveStatus = asyncHandler(async (req, res) => {
  const { leaveId, status, } = req.body;
  const { rejectionReason } = req.body || {};

  console.log("This is the rejected reason", rejectionReason);
  const admin = req.admin;

  if (!leaveId || !status) {
    throw new APIError(400, "Leave ID and status are required");
  }

  if (status == "rejected" && !req.body.rejectionReason) {
    throw new APIError(400, "Leave rejected reason is required");
  }

  try {
    const leaveRecord = await LeaveModel.findById(leaveId);

    if (!leaveRecord) {
      throw new APIError(404, "Leave record not found");
    }

    if (leaveRecord.adminId.toString() !== admin._id.toString()) {
      throw new APIError(
        403,
        "You don't have permission to update this leave record"
      );
    }

    leaveRecord.status = status;
    leaveRecord.rejectedReason = rejectionReason || null;
    leaveRecord.updatedAt = new Date();
    await leaveRecord.save();

    return res
      .status(200)
      .json(new APIresponse(200, {}, "Leave status updated successfully"));
  } catch (error) {
    throw new APIError(
      500,
      `Failed to update leave status: ${error.message}`
    );
  }
});

const updateAttendance = asyncHandler(async (req, res) => {
  try {
    const { employeeId, date, newStatus, newRemarks } = req.body;
    const admin = req.admin;

    console.log("This is the body of the request", req.body);

    if (!employeeId || !date || !newStatus) {
      throw new APIError(
        400,
        "Employee ID, date, and newStatus are required"
      );
    }

    // const employee = await EmployeeModel.findOne({
    //   employeeId,
    //   adminId: admin._id,
    // });
    // if (!employee) {
    //   throw new APIError(
    //     403,
    //     "This employee does not belong to the authenticated admin"
    //   );
    // }

    // console.log(employee)

    // const Id = employee._id

    const updatedRecord = await AttendanceModel.findOneAndUpdate(
      { _id: employeeId},
      {
        $set: {
          attendanceStatus: newStatus,
          remarks: newRemarks || "",
        },
      },
      { new: true }
    );

    if (!updatedRecord) {
      throw new APIError(
        404,
        "No attendance record found for this employee on the specified date"
      );
    }

    return res
      .status(200)
      .json(
        new APIresponse(200, updatedRecord, "Attendance updated successfully")
      );
  } catch (error) {
    console.error("Error at update attendance: ", error)
    throw new APIError(500, `Failed to update attendance: ${error.message}`);
  }
});

export {
  registerAdmin,
  loginAdmin,
  logoutAdmin,
  refreshAccessToken,
  getAdminProfile,
  updateAdminProfile,
  changeAdminPassword,
  registerEmployee,
  getEmployees,
  updateEmployee,
  deleteEmployee,
  getEmployeeDetails,
  markAttendance,
  getHistory,
  getLeaveDetails,
  setLeaveStatus,
  updateAttendance
};
