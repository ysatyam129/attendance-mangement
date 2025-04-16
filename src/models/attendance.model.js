import mongoose, { Schema } from "mongoose";
import { EMPLOYEE_ATTENDANCE_STATUS, EMPLOYEE_SHIFT } from "../constants"; 

const attendanceSchema = new Schema(
  {
    adminId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Admin",
      required: true,
      index: true,
    },
    employeeId: {
      type: mongoose.Schema.Types.String,
      ref: "Employee",
      required: true,
      index: true,
    },
    shiftDetails: {
      type: String,
      enum: EMPLOYEE_SHIFT,
      required: true,
    },
    status: {
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
