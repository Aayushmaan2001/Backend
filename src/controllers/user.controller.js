import { asyncHandler } from "../utils/asyncHandler.js";
import { ApiError } from "../utils/ApiError.js";
import { User } from "../models/user.models.js";
import { uploadOnCloudinary } from "../utils/cloudinary.js";
import { ApiResponse } from "../utils/ApiResponse.js";
import cookieParser from "cookie-parser";
import jwt from "jsonwebtoken"

const generateAccessAndRefreshTokens = async(userId) => {
    try {
       const user =  await User.findById(userId)
     const accessToken =   user.generateAccessToken()
      const refreshToken =  user.generateRefreshToken()

        user.refreshToken = refreshToken
        await user.save({ validateBeforeSave: false })

        return(accessToken  , refreshToken)

    } catch (error) {
        throw new ApiError(500 , "Something went wrong while genrating access and refresh tokens")
    }
}

const registerUser = asyncHandler( async (req,res) => {
    // get User Deatails from Frontend
    // validation - check for  not empty
    // check if user already exists  --check for username and email both
    // check for coverImage and check for avatar (compulsary)
    // upload them on cloudinary , avatar
    // create user Object - create Entry in DB
    // remove password and refresh token field from response
    // check for user creation
    // return response

    // Get user details from Frontend
    const {fullName , username , email , password } = req.body
    console.log("email : " , email);


    
    
    // validation  - check for not empty
    
    if([fullName , email , username ,password].some((field) =>  field?.trim() === "")){
        throw new ApiError (400 , "All fields are required")
    }
    // check if user already existed

   const existedUser = await User.findOne({
        $or: [{username } , {email}]
    })

    if(existedUser){
       throw new ApiError (409 , "User with email or username already existed")
    }

    //check for files(images)
   const avatarLocalPath =  req.files?.avatar[0]?.path;
//    const coverImageLocalPath = req.files?.coverImage[0]?.path;

   let coverImageLocalPath;
   if(req.files && Array.isArray(req.files.coverImage) && req.files.coverImage.length>0){
    coverImageLocalPath = req.files.coverImage[0].path
   }

    //check for avatar
   if(!avatarLocalPath){
    throw new ApiError (400 , "Avatar is required")
   }
   //upload on cloudinary
   const avatar = await uploadOnCloudinary(avatarLocalPath)
   const coverImage = await uploadOnCloudinary(coverImageLocalPath)

   //check for avatar on cloudinary

   if(!avatar){
    throw new ApiError(400 , "Avatar is required")
   }

   const user =  await User.create(
    {
        fullName,
        username: username.toLowerCase(), 
        email,
        password,
        avatar: avatar.url,
        coverImage: coverImage?.url || ""            //check for coverImage (validation for coverImage)
    }
   )

   //check for user creation in DB
   const createdUserInDB = await User.findById(user._id).select(
    " -password -refreshToken"
   )

   if(!createdUserInDB){
    throw new ApiError (500 , "Something went wrong while regestering the user!")
   }

   // return response
   return res.status(201).json(
    new ApiResponse(200 , createdUserInDB , "User registered successfully")
   )


   
} )

const loginUser = asyncHandler(async (req,res) => {
    // req body --> data
    // username or email
    // find the user
    // password check
    // access and refresh token 
    //send acess and refresh token by cookie


    //grab the data from req body
    const {email, username , password} = req.body


    //login with username or eamil 
    if(!(username || email)){
        throw new ApiError (404 , "username or email is required")
    }

    //find user with existed username or email
  const user =  await User.findOne({
        $or: [{ username} ,{email}]
    })

    //if user not found
    if(!user){ 
        throw new ApiError(404 , "user does not exist")
    }
    // check for password

   const isPasswordValid =  await user.isPasswordCorrect(password)

   if(!isPasswordValid){
    throw new ApiError(401 , "password is incorrect")
   }

    const [accessToken , refreshToken] =  await generateAccessAndRefreshTokens(user._id)

    const loggedInUser = await User.findById(user._id).select("-password  refreshToken")

    const options = {
        httpOnly: true,
        secure: true
    }

    return res.status(200).cookie("accessToken" , accessToken , options).cookie("refreshToken" , refreshToken , options).json(
       new ApiResponse(
        200,
        {
            user: loggedInUser , accessToken , refreshToken
        },
        "User logged In Successfully"
       )
    )

})

const logoutUser = asyncHandler(async(req,res) =>{
    await User.findByIdAndUpdate(
        req.user._id,
        {
            $set: {
                refreshToken : undefined
            }
        },
        {
            new : true
        }
    )
    const options = {
        httpOnly: true,
        secure: true
    }

    return res.status(200).clearCookie("accessToken" , options).clearCookie("refreshToken" , options).json(
        new ApiResponse(200 , {}  ,"user logged out successfully")
    )
})


const refreshAccessToken = asyncHandler(async(req,res) => {
   const incomingRefreshToken =  req.cookies.refreshToken || req.body.refreshToken

   if(!incomingRefreshToken){
    throw new ApiError((401 , "unauthorized request"))
   }

 try {
     const decodedToken = jwt.verify(incomingRefreshToken , process.env.REFRESH_TOKEN_SECRET)
   
     const user =  await User.findById(decodedToken?._id)
   
     if(!user){
       throw new ApiError((401 , "Invalid refresh token"))
      }
   
      if(incomingRefreshToken !== user?.refreshToken){
       throw new ApiError((401 , "Refresh token is expired or used"))
      }
   
      const options = {
       httpOnly: true,
       secure: true
      }
   
    const {accessToken , newRefreshToken} = await generateAccessAndRefreshTokens(user._id)
   
      return res.status(200).cookie("accessToken" , accessToken, options).cookie("refreshToken" ,refreshToken , options).json(
       new ApiResponse(
           200 , {accessToken , newRefreshToken : newRefreshToken} , "access token refreshed"
       )
      )
 } catch (error) {
    throw new ApiError (401 , error?.message || "Invalid refreshTOken")
 }

})

const changeCurrentPassword = asyncHandler(async(req,res) => {
    const {oldPassword , newPassword} = req.body

   const user =  await User.findById(req.user?._id)
  const isPasswordCorrect = await user.isPasswordCorrect(oldPassword)

  if(!isPasswordCorrect){
    throw new ApiError (400 , "Invaild old Password!")
  }

    user.password = newPassword
    await user.save({validateBeforeSave : false})

    return res.status(200).json(new ApiResponse(200 , {} , "Password Change Successfully"))
})

const getCurrentUser = asyncHandler(async(req,res) => {
   return res.status(200).json(200 , req.user , "current user fetch sucessfully")
})

const updateAccountDetails  = asyncHandler(async(req,res) =>{
    const {fullName , email , } = req.body

    if(!fullName || !email) {
        throw new Api (400 , "All fields are required")
    }

   const user =  await User.findByIdAndUpdate(
    req.user?._id ,
     {
        $set :{
            fullName : fullName,
            email: email
        }
     } , 
     {new: true}
    ).select("-password")

    return res
    .status(200)
    .json(
        new ApiResponse(200 , user , "Account details updated successfully.")
        )
})
const updateUserAvatar = asyncHandler(async(req,res) => {
    const avatarLocalPath = req.file?.path

    if(!avatarLocalPath){
        new ApiError , ("Avatar file is missing")
    }

    const avatar = await uploadOnCloudinary(avatarLocalPath)

    if(!avatar.url){
        new ApiError , ("Error while uploading on avatar!")
    }

   const user =  await User.findByIdAndUpdate(
        req.user?._id,
        {
            $set: {
                avatar : avatar.url
            }
        },
        {new: true}

    ).select("-password")

    return res.status(200).json(
        new ApiResponse (200 , user , "Avatar Image updated succesfully")
    )
})
const updateUserCoverImage = asyncHandler(async(req,res) => {
    const coverImageLocalPath = req.file?.path

    if(!coverImageLocalPath){
        new ApiError , ("coverImage file is missing")
    }

    const coverImage = await uploadOnCloudinary(coverImageLocalPath)

    if(!coverImage.url){
        new ApiError , ("Error while uploading on coverIimage!")
    }

   const user =  await User.findByIdAndUpdate(
        req.user?._id,
        {
            $set: {
                coverImage : coverImage.url
            }
        },
        {new: true}

    ).select("-password")

    return res.status(200).json(
        new ApiResponse (200 , user , "coverImage updated succesfully")
    )
})

export {
     registerUser ,
     loginUser , 
     logoutUser ,
     refreshAccessToken , 
     changeCurrentPassword ,
     getCurrentUser,
     updateUserAvatar,
     updateUserCoverImage
    }