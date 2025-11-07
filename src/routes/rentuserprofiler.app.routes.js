/**
 * @fileoverview App routes for User Profile.
 * Connects to the app-specific profile controllers.
 */

import express from "express";
import { upload } from "../middlewares/multer.middlewares.js";
import { verifyJWT } from "../middlewares/auth.middlewares.js";

// Import APP controllers from the new app-specific controller file
import {
  uploadProfilePhoto,
  updateBasicInfo,
  updateMobileNumber,
  updateUserProfile,
  uploadVerificationDoc,
} from "../controllers/rentuserprofile.app.controller.js"; // <-- Note '.app'

const router = express.Router();

// Routes for specific updates
router.post(
  "/upload-photo",
  verifyJWT,
  upload.single("photo"),
  uploadProfilePhoto
);
router.patch("/update-basic", verifyJWT, updateBasicInfo);
router.patch("/update-mobile", verifyJWT, updateMobileNumber);

// --- App-Only Routes ---

// This endpoint handles updating name, dob, phone, etc. from the profile screen
router.patch("/update", verifyJWT, updateUserProfile);

// This is the new route for uploading verification documents
router.post(
  "/upload-doc",
  verifyJWT,
  upload.single("document"),
  uploadVerificationDoc
);

export default router;