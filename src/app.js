import express from "express"
import cors from 'cors'
import cookieParser from "cookie-parser"

const app = express()

// app.use(cors({
//     origin: process.env.CORS_ORIGIN,
//     credentials:true,

// }))
app.use(
    cors({
      origin:"https://atm.indibus.net/",
      credentials: true,
    })
  );
app.use(express.json({
    limit:'16kb'
}))
app.use(express.urlencoded({
    extended:true,
    limit:'16kb'
}))
app.use(express.static("public"))
app.use(cookieParser())


import adminRoutes from "./routes/admin.routes.js"
app.use("/api/v1/", adminRoutes)


import employeeRoutes from "./routes/employee.routes.js"
app.use("/api/v1/employee", employeeRoutes)
export default app;

app.use((err, req, res, next) => {
  if (process.env.NODE_ENV === "development") {
    console.error(err);
  }

  const statusCode = err.statusCode || 500;

  return res.status(statusCode).json({
    success: false,
    message: err.message || "Internal Server Error",
    errors: err.errors || [],
    data: null,
  });
});