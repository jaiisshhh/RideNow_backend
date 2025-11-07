/**
 * @fileoverview App-specific controllers for user profile.
 *
 * These functions are designed for the RideNow mobile app.
 * They use 'try...catch' blocks for error handling and
 * return JSON-formatted 'apiresponse' objects on all paths.
 */

import { User } from "../models/rentuser.model.js";
import { uploadOnCloudinary } from "../utils/cloudinary.js";
import { apiresponse } from "../utils/apiresponse.js";

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

    // Note: App file was using req.file.buffer.
    // If multer is configured for 'path' (like in the user controller), use req.file.path.
    // Sticking to your file's original 'req.file.buffer' logic.
    const uploadResult = await uploadOnCloudinary(req.file.buffer);
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
      .json(new apiresponse(500, null, "Internal Server Error"));
  }
};

const updateBasicInfo = async (req, res) => {
  try {
    const { name, dob } = req.body;

    if (!name || !dob) {
      return res
        .status(400)
        .json(
          new apiresponse(400, null, "Name and Date of Birth are required")
        );
    }

    const parsedDob = new Date(dob);
    if (isNaN(parsedDob.getTime())) {
      return res
        .status(400)
        .json(
          new apiresponse(
            400,
            null,
            "Invalid date format for DOB. Use YYYY-MM-DD."
          )
        );
    }

    const user = await User.findById(req.user._id);
    if (!user) {
      return res.status(404).json(new apiresponse(404, null, "User not found"));
    }

    user.name = name;
    user.dob = parsedDob;
    await user.save({ validateBeforeSave: false });

    return res.status(200).json(
      new apiresponse(
        200,
        { name: user.name, dob: user.dob }, // App returns correct user.name
        "Basic info updated successfully"
      )
    );
  } catch (error) {
    console.error("APP UPDATE BASIC INFO FAILED:", error);
    return res
      .status(500)
      .json(new apiresponse(500, null, "Internal Server Error"));
  }
};

const updateMobileNumber = async (req, res) => {
  try {
    const { mobileNumber } = req.body;

    const mobileRegex = /^[6-9]\d{9}$/;
    if (!mobileRegex.test(mobileNumber)) {
      return res
        .status(400)
        .json(new apiresponse(400, null, "Invalid Indian mobile number"));
    }

    const user = await User.findById(req.user._id);
    if (!user) {
      return res.status(404).json(new apiresponse(404, null, "User not found"));
    }

    user.phone = mobileNumber;
    user.isPhoneVerified = false; // APP-SPECIFIC: Reset verification status
    await user.save({ validateBeforeSave: false });

    return res
      .status(200)
      .json(
        new apiresponse(
          200,
          { phone: user.phone, isPhoneVerified: user.isPhoneVerified },
          "Mobile number updated. Please verify."
        )
      );
  } catch (error) {
    console.error("APP UPDATE MOBILE FAILED:", error);
    return res
      .status(500)
      .json(new apiresponse(500, null, "Internal Server Error"));
  }
};

/**
 * [APP-ONLY] Updates multiple user profile fields at once.
 */
const updateUserProfile = async (req, res) => {
  try {
    const { name, dob, phone } = req.body;
    const userId = req.user._id;

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json(new apiresponse(404, null, "User not found"));
    }

    if (name) user.name = name;
    if (dob) user.dob = new Date(dob);
    if (phone) {
      user.phone = phone;
      user.isPhoneVerified = false;
    }

    const updatedUser = await user.save({ validateBeforeSave: false });
    const userToReturn = await User.findById(updatedUser._id).select(
      "-password -refreshToken -otp"
    );

    return res
      .status(200)
      .json(new apiresponse(200, userToReturn, "Profile updated successfully"));
  } catch (error) {
    console.error("APP UPDATE USER PROFILE FAILED:", error);
    return res
      .status(500)
      .json(new apiresponse(500, null, "An internal server error occurred"));
  }
};

/**
 * [APP-ONLY] Uploads a verification document (Aadhar/License).
 */
const uploadVerificationDoc = async (req, res) => {
  try {
    const { docType } = req.body;
    const userId = req.user._id;

    // 1. Validate input
    if (!req.file) {
      return res
        .status(400)
        .json(new apiresponse(400, null, "Document file is required."));
    }
    if (!["aadhar", "license"].includes(docType)) {
      return res
        .status(400)
        .json(new apiresponse(400, null, "Invalid document type specified."));
    }

    // 2. Find the user
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json(new apiresponse(404, null, "User not found"));
    }

    // 3. Upload the file to Cloudinary
    // Note: Using req.file.path as seen in your app's user controller.
    const uploadResult = await uploadOnCloudinary(req.file.path);
    if (!uploadResult) {
      return res
        .status(500)
        .json(new apiresponse(500, null, "Document upload failed"));
    }

    // 4. Update the user's document in the database
    user.verifiedDoc = {
      docType: docType,
      docUrl: uploadResult.secure_url,
      status: "pending", // Set status to pending for admin verification
    };
    await user.save({ validateBeforeSave: false });

    const userToReturn = await User.findById(userId).select(
      "-password -refreshToken -otp"
    );

    return res
      .status(200)
      .json(
        new apiresponse(
          200,
          userToReturn,
          `${docType} uploaded successfully. Awaiting verification.`
        )
      );
  } catch (error) {
    console.error("APP UPLOAD VERIFICATION DOC FAILED:", error);
    return res
      .status(500)
      .json(new apiresponse(500, null, "An internal server error occurred"));
  }
};

// Export all app-specific functions
export {
  uploadProfilePhoto,
  updateBasicInfo,
  updateMobileNumber,
  updateUserProfile,
  uploadVerificationDoc,
};
