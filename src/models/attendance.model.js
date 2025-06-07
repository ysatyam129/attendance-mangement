import mongoose, { Schema } from "mongoose";
import { EMPLOYEE_ATTENDANCE_STATUS, EMPLOYEE_SHIFT } from "../constants.js"; 

const attendanceSchema = new Schema(
  {
    adminId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Admin",
      required: true,
      index: true,
    },
    employeeId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Employee",
      required: true,
      index: true,
    },
    attendanceStatus: {
      type: String,
      enum: EMPLOYEE_ATTENDANCE_STATUS,
      required: true,
    },
    date: {
      type: Date,
      default: Date.now,
      required: true,
    },
    remarks: {
      type: String,
      default: "",
    },
  },
  {
    timestamps: true,
  }
);

const AttendanceModel = mongoose.model("Attendance", attendanceSchema);

export default AttendanceModel
