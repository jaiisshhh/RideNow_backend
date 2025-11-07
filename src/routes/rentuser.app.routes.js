/**
 * @fileoverview App routes for User Authentication.
 * Connects to the app-specific controllers.
 */

import express from "express";

// Import APP controllers from the new app-specific controller file
import {
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
} from "../controllers/rentuser.app.controller.js"; // <-- Note the '.app'
import { verifyJWT } from "../middlewares/auth.middlewares.js";

const router = express.Router();

// ================= Public App Routes =================
router.post("/register", registerUser);
router.post("/verify-otp", verifyOtp);
router.post("/login", login);
router.post("/google-login", googleLogin);
router.post("/refresh-token", refreshAccessToken);
router.post("/forgot-password", forgotPassword);
router.post("/reset-password", resetPassword);

// ================= Protected App Routes =================
router.post("/logout", verifyJWT, logout);
router.post("/change-password", verifyJWT, changePassword);

router.get("/current-user", verifyJWT, getCurrentUser);
export default router;