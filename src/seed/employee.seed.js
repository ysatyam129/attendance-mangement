import mongoose from "mongoose";
import bcrypt from "bcrypt";
import dotenv from "dotenv";
import Employee from "../models/employee.model.js";
import { DB_NAME } from "../constants.js";

dotenv.config({ path: "./.env" });

const employees = [
  {
    employeeId: "EMP001",
    fullname: "Alice Johnson",
    email: "alice@example.com",
    phone: 1234567890,
    designation: "Software Engineer",
    department: "Engineering",
    joiningDate: new Date("2022-03-15"),
    employeeType: "Full-Time",
    shiftDetails: "Morning",
    status: "active",
    password: "password123",
    adminId: "60d5f9b3f8d2c43d2c8b4567",
  },
  {
    employeeId: "EMP002",
    fullname: "Bob Smith",
    email: "bob@example.com",
    phone: 9876543210,
    designation: "Product Manager",
    department: "Product",
    joiningDate: new Date("2023-01-10"),
    employeeType: "Contract",
    shiftDetails: "Night",
    status: "inactive",
    password: "securePass456",
    adminId: "60d5f9b3f8d2c43d2c8b4567",
  },
];

const hashPasswords = async (data) => {
  const saltRounds = 10;
  return Promise.all(
    data.map(async (emp) => {
      const hashedPassword = await bcrypt.hash(emp.password, saltRounds);
      return { ...emp, password: hashedPassword };
    })
  );
};

mongoose
  .connect(process.env.MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
    dbName: DB_NAME,
  })
  .then(async () => {
    console.log("Connected to MongoDB");

    const employeesWithHashedPasswords = await hashPasswords(employees);
    await Employee.insertMany(employeesWithHashedPasswords);

    console.log("Employee data seeded with hashed passwords!");
  })
  .catch((err) => {
    console.error("MongoDB connection error:", err);
  })
  .finally(async () => {
    await mongoose.disconnect();
    console.log("Disconnected from MongoDB");
  });
