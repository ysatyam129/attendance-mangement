import mongoose, {Schema} from "mongoose"
import jwt from 'jsonwebtoken'
import bcrypt from "bcrypt"
import {
  EMPLOYEE_STATUS,
  EMPLOYEE_TYPES,
  EMPLOYEE_SHIFT,
  EMPLOYEE_ATTENDANCE_STATUS,
} from "../constants.js";

const employeeSchema = new Schema(
  {
    employeeId: {
      type: String,
      required: true,
      unique: true,
      trim: true,
      index: true,
    },
    fullname: {
      type: String,
      lowercase: true,
      trim: true,
    },
    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
      index: true,
    },
    phoneNumber: {
      type: Number,
      required: true,
    },
    designations: {
      type: String,
      required: true,
    },
    department: {
      type: String,
      required: true,
    },
    joiningDate: {
      type: Date,
      required: true,
    },
    employeeType: {
      type: String,
      enum: EMPLOYEE_TYPES,
      required: true,
    },
    shiftDetails: {
      type: String,
      enum: EMPLOYEE_SHIFT,
      required: true,
    },
    status: {
      type: String,
      enum: EMPLOYEE_STATUS,
      default: "active",
    },
    attendanceStatus: {
      type: String,
      enum: EMPLOYEE_ATTENDANCE_STATUS,
      default: "Mark",
    },
    password: {
      type: String,
      required: [true, "Password is Required"],
    },
    adminId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Admin",
      required: true,
    },
    refreshToken: {
      type: String,
    },
  },
  {
    timestamps: true,
  }
);

employeeSchema.pre("save", async function (next) {
  if (!this.isModified("password")) return next();
  this.password = await bcrypt.hash(this.password, 10);
  next();
});

employeeSchema.methods.isPasswordCorrect = async function (password) {
  return await bcrypt.compare(password, this.password);
};

employeeSchema.methods.generateAccessToken = function () {
  return jwt.sign(
    {
      _id: this._id,
      email: this.email,
      username: this.username,
      fullname: this.fullname,
    },
    process.env.ACCESS_TOKEN_SECRET,
    {
      expiresIn: process.env.ACCESS_TOKEN_EXPIRY,
    }
  );
};
employeeSchema.methods.generateRefreshToken = function () {
  return jwt.sign(
    {
      _id: this._id,
    },
    process.env.REFRESH_TOKEN_SECRET,
    {
      expiresIn: process.env.REFRESH_TOKEN_EXPIRY,
    }
  );
};

const EmployeeModel = mongoose.model("Employees", employeeSchema);

export default EmployeeModel
