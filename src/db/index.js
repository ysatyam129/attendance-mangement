import mongoose from "mongoose"
import { DB_NAME } from "../constants.js"

const connectDB = async () => {
  try {
    mongoose.set('bufferCommands', false);
    mongoose.set('bufferMaxEntries', 0);
    
    const connectInstance = await mongoose.connect(`${process.env.MONGO_URI}/${DB_NAME}`, {
      serverSelectionTimeoutMS: 30000,
      socketTimeoutMS: 45000,
      bufferCommands: false,
      bufferMaxEntries: 0
    });
    
    console.log(`MongoDB Connected !! DB host : ${connectInstance.connection.host}`);
  } catch (error) {
    console.log("Error: " + error);
    process.exit(1);
  }
}

export default connectDB
