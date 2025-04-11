import connectDB from "./db/index.js";
import dotenv from "dotenv"
import app from "./app.js"
import adminRouter from "./routes/admin.routes.js";
import employeeRouter from "./routes/employee.routes.js";

dotenv.config({
    path:'./.env'
})

connectDB()
  .then(()=>{
    app.on("error",(error)=>{
    console.log("Some Error Happened in ./src/index.js before listening to app");
    })
    app.listen(process.env.PORT||8080,()=>{
      console.log({
        serverStatus:"🌐  Application is Running", 
        URL:"http://localhost:8080"
      });
    })
  })
  .catch((error)=>{
    console.log("DB connection Failed from Index.js");
  })

app.use("/api/admin", adminRouter);
app.use("/api/employee", employeeRouter);