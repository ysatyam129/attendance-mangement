import { asyncHandler } from "../utils/asyncHandler.js";
import { APIError } from "../utils/APIerror.js";
import { User } from "../models/user.model.js";
import { uploadOnCloudinary } from "../utils/cloudinary.js";
import { APIresponse } from "../utils/APIresponse.js";
import jwt  from "jsonwebtoken";

const generateAccessTokenAndRefreshToken = async(userId)=>{
    try {
        const user = await User.findById(userId)
        const accessToken = user.generateAccessToken()
        const refreshToken = user.generateRefreshToken()


        user.refreshToken = refreshToken
        await user.save({validateBeforeSave:false})

        return {accessToken,refreshToken}

    } catch (error) {
        throw new APIError(500,"Something Went wrong while generating access and refresh Token")
    }
}

const registerUser = asyncHandler(async (req,res) => {
     //get userDatails from FrontEnd 
     //validation - nOT EMPTY
     // Check if user already Exists : uSERNAME AND EMAIL
     //Check Files: CoverImages and Avatar
     //Upload on Cloudinary
     //create user object - create entry in db
     // remove password and refresh token Field from response
     //check for user creation 
     //return response

     //get userDatails from FrontEnd 
    const {username,email,fullname,password} = req.body
    console.log("email:",email);

    //validation - nOT EMPTY
    if(
        [fullname,email,username,password].some((field)=> field?.trim() === "")
    ){
        throw new APIError(400,"No Empty Field is allowed")
    }

    // Check if user already Exists : uSERNAME AND EMAIL
    const existedUser = await User.findOne({
        $or: [{username},{email}]
    })

    if(existedUser){
        throw new APIError(409,"User with Email or Username already exists")

    }
    
    //Check Files: CoverImages and Avatar
    const avatarLocalPath = req.files?.avatar[0]?.path
    // const coverImageLocalPath = req.files?.coverImage[0]?.path
   
    let coverImageLocalPath
    if(req.files && Array.isArray(req.files.coverImage) && req.files.coverImage.length > 0){
        coverImageLocalPath = req.files.coverImage[0].path
    }

    if (!avatarLocalPath){
        throw new APIError(400,"Avatar file is Required")
    }
    //Upload on Cloudinary
    const avatar = await uploadOnCloudinary(avatarLocalPath)
    const coverImage = await uploadOnCloudinary(coverImageLocalPath)
    if(!avatar){
        throw new APIError(400,"Avatar file is Required")
    }

    //create user object - create entry in db
    const user = await User.create({
        fullname,
        avatar: avatar.url,
        coverImage:coverImage?.url || "",
        email,
        password,
        username:username.toLowerCase()
    })
    
    const createdUser =await User.findById(user._id).select(
        "-password -refreshToken"
    )
    


    if(!createdUser){
        throw new APIError(500,"Something went wrong while Registering the User")
    }

    return res.status(201).json(
        new APIresponse(200,createdUser,"User Registered Succesfully")
    )
})

const loginUser = asyncHandler(async (req,res)=>{
    // take data from Req body 
    // validation if any field is empty
    // find user in database
    // check Password
    // generate AccessToken and Refresh Token
    // send Cookies
    //response of successfull transfer

    const { email,username,password } = req.body
    
    if(!(username || email)){
        throw new APIError(400,"Username and Email required")
    }
                

    const user = await User.findOne({
        $or:[{username},{email}]
    })
    if(!user){
        throw new APIError(404,"User Does Not Exist")
    }
    
    const isPasswordValid = await user.isPasswordCorrect(password)
    if(!isPasswordValid){
        throw new APIError(401,"Password is Incorrect")
    }

    const {accessToken,refreshToken}=await generateAccessTokenAndRefreshToken(user._id)

    const loggedInUser = await User.findById(user._id).select("-password -refreshToken ")


    const options = {
        httpOnly:true,
        secure:true
    }

    return res
    .status(200)
    .cookie("accessToken",accessToken,options)
    .cookie("refreshToken",refreshToken,options)
    .json(
        new APIresponse(
            200,
            {
                user:loggedInUser,accessToken,refreshToken
            },
            "User Logged In successfully"
        )
    )

})

const logoutUser = asyncHandler(async (req,res)=>{
    //clear cookies 
    await User.findByIdAndUpdate(
        req.user._id,
        {
            $set:{
                refreshToken:undefined
            }
        },
        {
            new: true
        }
    ) 

    const options = {
        httpOnly:true,
        secure:true
    }
    return res
    .status(200)
    .clearCookie("accessToken")
    .clearCookie("refreshToken")
    .json(new APIresponse(200,{},"User Logged Out"))
})

const refreshAccessToken = asyncHandler(async (req,res)=>{
    const incomingRefreshToken = req.cookies.refreshToken || req.body.refreshToken

    if (!incomingRefreshToken){
        throw new APIError(401,"Unauthorized request")
    }

    try {
        const decodedRefreshToken = jwt.verify(
            incomingRefreshToken,
            process.env.REFRESH_TOKEN_SECTRET
        )
    
        const user = await User.findById(decodedRefreshToken?._id)
    
        if(!user){
            throw new APIError(401,"Invalid Refresh Token")
        }
    
        if(incomingRefreshToken !== user?.refreshToken){
            throw new APIError(401,"Refresh token is expired or used")
        }
    
        const options = {
            httpOnly:true,
            secure:true
        }
    
        const {accessToken,newRefreshToken} = await generateAccessTokenAndRefreshToken(user._id)
    
        return res
        .status(200)
        .cookies("accessToken",accessToken,options)
        .cookies("refreshToken",newRefreshToken,options)
        .json(
            new APIresponse(200,{accessToken,refreshToken:newRefreshToken},"Access Token Refreshed")
        )
    } catch (error) {
        throw new APIError(401,error?.message||"Invalid Refresh Token")
    }
})

const changeCurrentPassword = asyncHandler(async (req,res)=>{
    const {newPassword,oldPassword} = req.body

    const user = await User.findById(req.user?._id)
    const isPasswordCorrect = await user.isPasswordCorrect(oldPassword)

    if(!isPasswordCorrect){
        throw new APIError(400,"Invalid Old Password")
    }
    user.password = newPassword
    await user.save({validateBeforeSave:false})

    return res
    .status(200)
    .json(200,{},"Password Changed Succesfully")

})

const getCurrentUser = asyncHandler(async (req,res)=>{
    return res
    .status(200)
    .json(200,req.user,"Current user Fetched Succefully")
})

const  updateAccountDetails = asyncHandler(async (req,res)=>{
    const {fullname,email} = req.body
    if(!(fullname || email)){
        throw new APIError(400,"All Fields are Required")
    }

    const user = await User.findByIdAndUpdate(
        req.user?._id,
        { 
            $set:{
                fullname,
                email:email
            }
        },
        {new:true}
    ).select("-password")
    return res
    .status(200)
    .json(new APIresponse(
        200,
        user,
        "Account details updated successfully"
    ))
    
})

const updateUserAvatar = asyncHandler(async (req,res)=>{
    const avatarLocalPath = req.file?.path

    if(!avatarLocalPath){
        throw new APIError(400,"Avatar file is missing")
    }

    const avatar = await uploadOnCloudinary(avatarLocalPath)

    if(!avatar){
        throw new APIError(400,"Something went wrong while uploading Avatar")
    }
    await User.findByIdAndUpdate(req.user?._id,
        {
            $set:{
                avatar:avatar.url
            }
        },
        {new:true}
    ).select("-password refreshToken")

    return res
    .status(200)
    .json(new APIresponse(200,{},"Avatar Updated Succesfully"))
})

const updateUserCoverImage = asyncHandler(async (req,res)=>{
    const coverImageLocalPath = req.file?.path

    if(!coverImageLocalPath){
        throw new APIError(400,"coverImage file is missing")
    }

    const coverImage = await uploadOnCloudinary(coverImageLocalPath)

    if(!coverImage){
        throw new APIError(400,"Something went wrong while uploading coverImage")
    }
    await User.findByIdAndUpdate(req.user?._id,
        {
            $set:{
                coverImage:coverImage.url
            }
        },
        {new:true}
    ).select("-password")

    return res
    .status(200)
    .json(new APIresponse(200,{},"CoverImage Updated Succfully"))
})

const getUserChannelProfile = asyncHandler(async (req,res)=>{
    const {username} = req.params

    if(!username?.trim()){
        throw new APIError(400,"Username not Find") 
    }
    const channel = await User.aggregate([
        {
            $match:{
                username: username?.toLowerCase()
            }
        },
        {
            $lookup:{
                from:"subcriptions",
                localField:"_id",
                foreignField:"channel",
                as:"subscribers"
            }
        },
        {
            $lookup:{
                from:"subscriptions",
                localField:"_id",
                foreignField:"subscriber",
                as:"subscribedTo"
            } 
        },
        {
            $addFields:{
                subscribersCount:{
                    $size:"$subscribers"
                },
                channelsSubscribedTo:{
                    $size:"$subscribedToo"
                },
                isSubscribed:{
                    $cond:{
                        if:{$in: [req.user?._id,"$subscribers.subscriber"]},
                        then:true,
                        else:false
                    }
                }
            }
        },
        {
            $project:{
                fullname:1,
                username:1,
                subscribersCount:1,
                channelsSubscribedTo:1,
                isSubscribed:1,
                email:1,
                avatar:1,
                coverImage:1,
            }
        }
    ])
    if(!channel?.length){
        throw new APIError(404,"channel does not exists")
    }
    console.log(channel)

    return res
    .status(200)
    .json(new APIresponse(200,channel[0],"User channel fetched Succfully"))
})

export {
    registerUser,
    loginUser,
    logoutUser,
    refreshAccessToken,
    changeCurrentPassword,
    getCurrentUser,
    updateAccountDetails,
    updateUserAvatar,
    updateUserCoverImage,
    getUserChannelProfile
}   