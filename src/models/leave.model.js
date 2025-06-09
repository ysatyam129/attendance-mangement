import mongoose, { Schema } from "mongoose";
import { EMPLOYEE_ATTENDANCE_STATUS, EMPLOYEE_SHIFT } from "../constants.js"; 

const leaveSchema = new Schema(
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
    leaveType: {
      type: String,
      enum: ["Sick Leave", "Casual Leave", "Paid Leave"],
      required: true,
    },
    startDate: {
      type: Date,
      required: true,
    },
    endDate: {
      type: Date,
      required: true,
    },
    reason: {
      type: String,
      required: true,
    },
    status: {
      type: String,
      enum: ["Pending", "Approved", "Rejected"],
      default: "Pending",
    },
    rejectedReason:{
      type: String,
      default: null,
    }
  },
  {
    timestamps: true,
  }
);

const LeaveModel = mongoose.model("Leave", leaveSchema);

export default LeaveModel
