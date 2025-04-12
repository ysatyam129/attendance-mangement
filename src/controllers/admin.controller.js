import jwt from "jsonwebtoken";
import Employee from "../models/employee.model.js";
import Admin from "../models/admin.model.js";
import { asyncHandler } from "../utils/asyncHandler.js";
import { APIError } from "../utils/APIerror.js";
import { APIresponse } from "../utils/APIresponse.js";
import { EMPLOYEE_TYPES, ADMIN_ROLES } from "../constants.js";



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

const validateShiftDetails = (shifts) => {
  if (!Array.isArray(shifts)) {
    return false;
  }

  for (const shift of shifts) {
    if (shift.shiftNumber === undefined || isNaN(shift.shiftNumber)) {
      return false;
    }

    if (!shift.date || isNaN(new Date(shift.date))) {
      return false;
    }

    if (!shift.startTime || isNaN(new Date(shift.startTime))) {
      return false;
    }

    if (!shift.endTime || isNaN(new Date(shift.endTime))) {
      return false;
    }

    const startTime = new Date(shift.startTime);
    const endTime = new Date(shift.endTime);

    if (endTime <= startTime) {
      return false;
    }
  }

  return true;
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
  console.log(req.body);

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

  const existedAdmin = await Admin.findOne({
    $or: [{ name }, { email }],
  });

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
  const { email,  password } = req.body;

  if ( !email) {
    throw new APIError(400, "Username or Email required");
  }

  if (email && !isValidEmail(email)) {
    throw new APIError(400, "Invalid email format");
  }

  

  if (!password || password.trim() === "") {
    throw new APIError(400, "Password is required");
  }

  const admin = await Admin.findOne({
    $or: [
     
      { email: email ? email.toLowerCase() : "" },
    ],
  });

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
  if (req.body.shiftDetails && !Array.isArray(req.body.shiftDetails)) {
    req.body.shiftDetails = [req.body.shiftDetails];
  }

  const {
    employeeId,
    fullname,
    email,
    phone,
    designations,
    joiningDate,
    employeeType,
    shiftDetails,
    password,
  } = req.body;

  const admin = req.admin

  if (
    !employeeId ||
    !fullname ||
    !email ||
    !phone ||
    !designations ||
    !employeeType ||
    !password
  ) {
    throw new APIError(400, "All required fields must be provided");
  }

  if (
    [employeeId, fullname, email, designations, employeeType, password].some(
      (field) => field.trim() === ""
    )
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

  if (!isStrongPassword(password)) {
    throw new APIError(
      400,
      "Password must be at least 8 characters long and include uppercase, lowercase, and numbers"
    );
  }

  if (joiningDate && !isValidDate(joiningDate)) {
    throw new APIError(400, "Invalid joining date format");
  }

  if (shiftDetails && !validateShiftDetails(shiftDetails)) {
    throw new APIError(400, "Invalid shift details format or values");
  }

  const existedEmployee = await Employee.findOne({
    $or: [{ employeeId }, { email }],
  });

  if (existedEmployee) {
    throw new APIError(409, "Employee with this ID or Email already exists");
  }

  const formattedJoiningDate = joiningDate ? new Date(joiningDate) : new Date();

  const formattedShiftDetails = shiftDetails
    ? shiftDetails.map((shift) => ({
        shiftNumber: shift.shiftNumber,
        date: new Date(shift.date),
        startTime: new Date(shift.startTime),
        endTime: new Date(shift.endTime),
      }))
    : [];

  try {
    const employee = await Employee.create({
      employeeId,
      fullname: fullname.toLowerCase(),
      email: email.toLowerCase(),
      phone,
      designations,
      joiningDate: formattedJoiningDate,
      employeeType,
      shiftDetails: formattedShiftDetails,
      password,
      adminId:admin._id,
    });

    const createdEmployee = await Employee.findById(employee._id).select(
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
  console.log(incomingRefreshToken);

  if (!incomingRefreshToken) {
    throw new APIError(401, "Unauthorized request - Refresh token missing");
  }

  try {
    const decodedToken = jwt.verify(
      incomingRefreshToken,
      process.env.REFRESH_TOKEN_SECRET
    );

    const employees = await Employee.find({ adminId: decodedToken._id })
      .select("-password -refreshToken")
      .sort({ createdAt: -1 });

    if (!employees) {
      throw new APIError(404, "No employees found for this admin");
    }

    return res
      .status(200)
      .json(new APIresponse(200, employees, "Employees fetched successfully"));
  } catch (error) {
    throw new APIError(400, `Unable to access employees details: ${error.message}`);
  }
});

const updateEmployee = asyncHandler(async (req, res) => {
  const { employeeId } = req.body;
  const admin = req.admin;

  if (!employeeId) {
    throw new APIError(400, "Employee ID is required");
  }

  const {
    fullname,
    email,
    phone,
    designations,
    joiningDate,
    employeeType,
    shiftDetails,
  } = req.body;

  if (req.body.shiftDetails && !Array.isArray(req.body.shiftDetails)) {
    req.body.shiftDetails = [req.body.shiftDetails];
  }

  const employee = await Employee.findById(employeeId);

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
    const existingEmployee = await Employee.findOne({
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

  if (employeeId) updateData.employeeId = employeeId;
  if (fullname) updateData.fullname = fullname.toLowerCase();
  if (email) updateData.email = email.toLowerCase();
  if (phone) updateData.phone = phone;
  if (designations) updateData.designations = designations;
  if (joiningDate) updateData.joiningDate = new Date(joiningDate);
  if (employeeType) updateData.employeeType = employeeType;

  if (shiftDetails) {
    updateData.shiftDetails = shiftDetails.map((shift) => ({
      shiftNumber: shift.shiftNumber,
      date: new Date(shift.date),
      startTime: new Date(shift.startTime),
      endTime: new Date(shift.endTime),
    }));
  }

  try {
    const updatedEmployee = await Employee.findByIdAndUpdate(
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

  const employee = await Employee.findById(employeeId);

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

    const deletedEmployee = await Employee.findByIdAndDelete(employeeId);

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
          { id: deletedEmployee._id },
          "Employee deleted successfully"
        )
      );
  } catch (error) {
    throw new APIError(500, `Failed to delete employee: ${error.message}`);
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
  deleteEmployee
};
