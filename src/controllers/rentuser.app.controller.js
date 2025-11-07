import { User } from "../models/rentuser.model.js";
import bcrypt from "bcryptjs"; // App file uses bcryptjs
import jwt from "jsonwebtoken";
import { OAuth2Client } from "google-auth-library";
import { apiresponse } from "../utils/apiresponse.js";
import { uploadOnCloudinary } from "../utils/cloudinary.js";
import validator from "validator";
import { generateOtp } from "../utils/generateotp.js";
import { sendEmail } from "../utils/sendemail.js";

// Note: All functions use try...catch blocks for robust error handling
// and return JSON responses, as required by the mobile app.

const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

// ================= Normal SignUp =================
const registerUser = async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password || email.trim() === "" || password.trim() === "") {
      return res
        .status(400)
        .json(new apiresponse(400, null, "Email and password are required"));
    }
    if (!validator.isEmail(email)) {
      return res
        .status(400)
        .json(new apiresponse(400, null, "Invalid email format"));
    }

    const existedUser = await User.findOne({ email });
    if (existedUser) {
      return res
        .status(409)
        .json(
          new apiresponse(409, null, "User with this email already exists")
        );
    }

    const otp = generateOtp();
    const hashedOtp = await bcrypt.hash(otp, 10);
    const otpExpiry = Date.now() + 10 * 60 * 1000; // 10 minutes

    await sendEmail(
      email,
      "Your OTP Code",
      `Your OTP code is ${otp}. It will expire in 10 minutes.`
    );

    const user = await User.create({
      email,
      password,
      otp: hashedOtp,
      otpExpiry,
      isEmailVerified: false,
    });

    return res
      .status(201)
      .json(
        new apiresponse(
          201,
          { userId: user._id },
          "OTP sent. Please verify your email."
        )
      );
  } catch (error) {
    console.error("APP REGISTER USER FAILED:", error);
    return res
      .status(500)
      .json(new apiresponse(500, null, "An internal server error occurred"));
  }
};

// ================= OTP Verification =================
const verifyOtp = async (req, res) => {
  try {
    const { email, otp } = req.body;

    if (!email || !otp) {
      return res
        .status(400)
        .json(new apiresponse(400, null, "Email and OTP are required"));
    }

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json(new apiresponse(404, null, "User not found"));
    }
    if (user.isEmailVerified) {
      return res
        .status(400)
        .json(new apiresponse(400, null, "Email is already verified"));
    }
    if (!user.otp || !user.otpExpiry || user.otpExpiry < Date.now()) {
      return res
        .status(400)
        .json(new apiresponse(400, null, "OTP is invalid or has expired"));
    }

    const isMatch = await bcrypt.compare(otp, user.otp);
    if (!isMatch) {
      return res
        .status(400)
        .json(new apiresponse(400, null, "Invalid OTP provided"));
    }

    user.isEmailVerified = true;
    user.otp = undefined;
    user.otpExpiry = undefined;
    await user.save({ validateBeforeSave: false });

    return res
      .status(200)
      .json(
        new apiresponse(
          200,
          null,
          "Email verified successfully. You can now login."
        )
      );
  } catch (error) {
    console.error("APP VERIFY OTP FAILED:", error);
    return res
      .status(500)
      .json(new apiresponse(500, null, "An internal server error occurred"));
  }
};

// ================= Normal Login =================
const login = async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res
        .status(400)
        .json(new apiresponse(400, null, "Email and password are required"));
    }

    const user = await User.findOne({ email, authProvider: "local" });
    if (!user) {
      return res
        .status(404)
        .json(new apiresponse(404, null, "User not found with this email"));
    }
    // APP-SPECIFIC: Check if email is verified
    if (!user.isEmailVerified) {
      return res
        .status(403)
        .json(
          new apiresponse(
            403,
            null,
            "Please verify your email before logging in."
          )
        );
    }

    const isPasswordCorrect = await user.isPasswordCorrect(password);
    if (!isPasswordCorrect) {
      return res
        .status(401)
        .json(new apiresponse(401, null, "Invalid user credentials"));
    }

    const accessToken = user.generateAccessToken();
    const refreshToken = user.generateRefreshToken();
    user.refreshToken = refreshToken;
    await user.save({ validateBeforeSave: false });

    const loggedInUser = await User.findById(user._id).select(
      "-password -refreshToken -otp"
    );
    const options = {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
    };
    // APP-SPECIFIC: Return tokens in JSON body
    const responseData = { user: loggedInUser, accessToken, refreshToken };

    return res
      .status(200)
      .cookie("accessToken", accessToken, options) // Also set cookies for potential webview use
      .cookie("refreshToken", refreshToken, options)
      .json(new apiresponse(200, responseData, "Login successful"));
  } catch (error) {
    console.error("APP LOGIN FAILED:", error);
    return res
      .status(500)
      .json(new apiresponse(500, null, "An internal server error occurred"));
  }
};

// ================= Google OAuth Login/Signup =================
const googleLogin = async (req, res) => {
  try {
    const { token } = req.body;
    if (!token) {
      return res
        .status(400)
        .json(new apiresponse(400, null, "Google token is required"));
    }

    const ticket = await client.verifyIdToken({
      idToken: token,
      audience: process.env.GOOGLE_CLIENT_ID,
    });
    const { email, name, picture, sub: googleId } = ticket.getPayload();

    let user = await User.findOne({ email });

    if (!user) {
      user = await User.create({
        email,
        name: name, // Note: App uses name
        profile: { photo: picture }, // Note: App uses profile.photo
        googleId: googleId,
        authProvider: "google",
        isEmailVerified: true,
      });
    } else if (user.authProvider !== "google") {
      // APP-SPECIFIC: Check for auth provider conflict
      return res
        .status(409)
        .json(
          new apiresponse(
            409,
            null,
            "This email is registered with a password. Please log in using your password."
          )
        );
    }

    const accessToken = user.generateAccessToken();
    const refreshToken = user.generateRefreshToken();
    user.refreshToken = refreshToken;
    await user.save({ validateBeforeSave: false });

    const loggedInUser = await User.findById(user._id).select(
      "-password -refreshToken -otp"
    );
    const options = {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
    };
    // APP-SPECIFIC: Return tokens in JSON body
    const responseData = { user: loggedInUser, accessToken, refreshToken };

    return res
      .status(200)
      .cookie("accessToken", accessToken, options)
      .cookie("refreshToken", refreshToken, options)
      .json(new apiresponse(200, responseData, "Google login successful"));
  } catch (error) {
    console.error("APP GOOGLE LOGIN FAILED:", error);
    return res
      .status(500)
      .json(
        new apiresponse(
          500,
          null,
          "An internal server error occurred during Google login"
        )
      );
  }
};

// ================= Logout =================
const logout = async (req, res) => {
  try {
    // req.user is attached by verifyJWT middleware
    await User.findByIdAndUpdate(
      req.user._id,
      { $set: { refreshToken: undefined } }, // Clear the refresh token
      { new: true }
    );

    const options = {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
    };

    return res
      .status(200)
      .clearCookie("accessToken", options)
      .clearCookie("refreshToken", options)
      .json(new apiresponse(200, {}, "Logged out successfully"));
  } catch (error) {
    console.error("APP LOGOUT FAILED:", error);
    return res
      .status(500)
      .json(new apiresponse(500, null, "An internal server error occurred"));
  }
};

// ================= Refresh Access Token =================
// (Logic ported from web controller and adapted for App)
const refreshAccessToken = async (req, res) => {
  try {
    // APP-SPECIFIC: Read token from body OR cookies
    const incomingRefreshToken = req.cookies?.refreshToken || req.body?.refreshToken;
    if (!incomingRefreshToken) {
      return res.status(401).json(new apiresponse(401, null, "No refresh token provided"));
    }

    const decoded = jwt.verify(
      incomingRefreshToken,
      process.env.REFRESH_TOKEN_SECRET
    );

    const user = await User.findById(decoded._id);
    if (!user || user.refreshToken !== incomingRefreshToken) {
      return res.status(403).json(new apiresponse(403, null, "Invalid refresh token"));
    }

    const newAccessToken = user.generateAccessToken();
    const newRefreshToken = user.generateRefreshToken(); // Token rotation
    user.refreshToken = newRefreshToken;
    await user.save({ validateBeforeSave: false });

    const options = {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
    };

    return res
      .status(200)
      .cookie("accessToken", newAccessToken, options)
      .cookie("refreshToken", newRefreshToken, options)
      .json(
        new apiresponse(
          200,
          { accessToken: newAccessToken, refreshToken: newRefreshToken }, // APP-SPECIFIC: Send new tokens in body
          "Token refreshed"
        )
      );
  } catch (error) {
    console.error("APP REFRESH TOKEN FAILED:", error);
    return res
      .status(403)
      .json(new apiresponse(403, null, "Invalid or expired refresh token"));
  }
};

// ================= Forgot Password =================
// (Logic ported from web controller and adapted for App)
const forgotPassword = async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) {
      return res.status(400).json(new apiresponse(400, null, "Email is required"));
    }

    const user = await User.findOne({ email, authProvider: "local" });
    if (!user) {
      return res.status(404).json(new apiresponse(404, null, "User not found"));
    }

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const otpExpiry = Date.now() + 15 * 60 * 1000;

    user.otp = otp;
    user.otpExpiry = otpExpiry;
    user.otpPurpose = "forgot";
    await user.save({ validateBeforeSave: false });

    await sendEmail(user.email, "Password Reset OTP", `Your OTP is ${otp}`);

    return res
      .status(200)
      .json(new apiresponse(200, {}, "OTP sent to email"));
  } catch (error) {
    console.error("APP FORGOT PASSWORD FAILED:", error);
    return res
      .status(500)
      .json(new apiresponse(500, null, "An internal server error occurred"));
  }
};

// ================= Reset Password =================
// (Logic ported from web controller and adapted for App)
const resetPassword = async (req, res) => {
  try {
    const { email, otp, newPassword } = req.body;
    if (!email || !otp || !newPassword) {
      return res.status(400).json(new apiresponse(400, null, "Email, OTP and new password are required"));
    }

    const user = await User.findOne({ email, authProvider: "local" });
    if (!user) {
      return res.status(404).json(new apiresponse(404, null, "User not found"));
    }

    if (user.otp !== otp || Date.now() > user.otpExpiry) {
      return res.status(400).json(new apiresponse(400, null, "Invalid or expired OTP"));
    }
    
    // Ensure this OTP was for 'forgot password'
    // if (user.otpPurpose !== 'forgot') {
    //   return res.status(400).json(new apiresponse(400, null, "Invalid OTP purpose"));
    // }

    user.password = newPassword; // Hashing will be done by the 'pre.save' hook in model
    user.otp = undefined;
    user.otpExpiry = undefined;
    user.otpPurpose = undefined;
    await user.save();

    return res
      .status(200)
      .json(new apiresponse(200, {}, "Password reset successful"));
  } catch (error) {
    console.error("APP RESET PASSWORD FAILED:", error);
    return res
      .status(500)
      .json(new apiresponse(500, null, "An internal server error occurred"));
  }
};

// ================= Change Password =================
// (Logic ported from web controller and adapted for App)
const changePassword = async (req, res) => {
  try {
    const { oldPassword, newPassword } = req.body;
    if (!oldPassword || !newPassword) {
      return res.status(400).json(new apiresponse(400, null, "Old and new password are required"));
    }

    const user = await User.findById(req.user._id); // req.user comes from verifyJWT
    if (!user) {
      return res.status(404).json(new apiresponse(404, null, "User not found"));
    }

    const isMatch = await user.isPasswordCorrect(oldPassword);
    if (!isMatch) {
      return res.status(400).json(new apiresponse(400, null, "Old password is incorrect"));
    }

    user.password = newPassword; // Hashing will be done by 'pre.save'
    await user.save();

    return res
      .status(200)
      .json(new apiresponse(200, {}, "Password changed successfully"));
  } catch (error) {
    console.error("APP CHANGE PASSWORD FAILED:", error);
    return res
      .status(500)
      .json(new apiresponse(500, null, "An internal server error occurred"));
  }
};

// ================= Upload Profile Photo =================
const uploadProfilePhoto = async (req, res) => {
  try {
    if (!req.file) {
      return res
        .status(400)
        .json(new apiresponse(400, null, "Photo file is required"));
    }

    const user = await User.findById(req.user._id);
    if (!user) {
      return res.status(404).json(new apiresponse(404, null, "User not found"));
    }

    const uploadResult = await uploadOnCloudinary(req.file.path);
    if (!uploadResult) {
      return res
        .status(500)
        .json(new apiresponse(500, null, "Photo upload failed"));
    }

    user.profile.photo = uploadResult.secure_url;
    await user.save({ validateBeforeSave: false });

    return res
      .status(200)
      .json(
        new apiresponse(
          200,
          { photo: user.profile.photo },
          "Profile photo uploaded successfully"
        )
      );
  } catch (error) {
    console.error("APP UPLOAD PHOTO FAILED:", error);
    return res
      .status(500)
      .json(new apiresponse(500, null, "An internal server error occurred"));
  }
};

// ================= Get Current User =================
const getCurrentUser = async (req, res) => {
  try {
    // req.user is already attached from the verifyJWT middleware
    const user = await User.findById(req.user._id).select(
      "-password -refreshToken -otp"
    );
    if (!user) {
      return res.status(404).json(new apiresponse(404, null, "User not found"));
    }
    return res
      .status(200)
      .json(new apiresponse(200, user, "Current user fetched successfully"));
  } catch (error) {
    console.error("APP GET CURRENT USER FAILED:", error);
    return res
      .status(500)
      .json(new apiresponse(500, null, "An internal server error occurred"));
  }
};

// Export all functions for the app routes
export {
  uploadProfilePhoto,
  login,
  googleLogin,
  refreshAccessToken,
  logout,
  forgotPassword,
  resetPassword,
  changePassword,
  registerUser,
  verifyOtp,
  getCurrentUser,
};