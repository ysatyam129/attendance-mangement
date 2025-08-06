import connectDB from "./db/index.js";
import dotenv from "dotenv"
import app from "./app.js"

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
        URL:"https://attendance-mangement.vercel.app"
      });
    })
  })
  .catch((error)=>{
    console.log("DB connection Failed from Index.js");
  })
