import express from "express";
import cors from "cors";
import cookieParser from "cookie-parser";
import dotenv from "dotenv";

dotenv.config({
  path: "./.env",
});

const app = express();

// 1. CORS updated to allow all origins (for web + app development)
app.use(
  cors({
    origin: "*",
    credentials: true,
  })
);

app.get("/", (req, res) => {
  res.send("✅ Server is running fine!");
});

// 2. Middlewares updated with safer limits
app.use(express.json({ limit: "16kb" }));
app.use(express.urlencoded({ extended: true, limit: "16kb" }));
app.use(cookieParser());

// --- 3. Route Imports (Web AND App) ---

// --- Web Routes (Existing) ---
import userRouter from "./routes/rentuser.routes.js";
import profileRouter from "./routes/rentuserprofiler.routes.js";
import hostRouter from "./routes/host.routes.js";
import hostProfileRouter from "./routes/hostprofile.route.js";
import vehicleRouter from "./routes/vehicle.routes.js";

// --- App Routes (NEW) ---
import userAppRouter from "./routes/rentuser.app.routes.js";
import profileAppRouter from "./routes/rentuserprofiler.app.routes.js";

// --- 4. Route Declarations (Web AND App) ---

// --- Web Route Declarations (Existing - Unchanged) ---
app.use("/api/v1/users", userRouter);
app.use("/api/v1/users/profile", profileRouter);
app.use("/api/v1/hosts", hostRouter);
app.use("/api/v1/hosts/profile", hostProfileRouter);
app.use("/api/v1/vehicles", vehicleRouter);

// --- App Route Declarations (NEW) ---
// We mount the app routes on a separate /app prefix
// This matches your client-side URL: http://.../api/v1/app
app.use("/api/v1/app/users", userAppRouter);
app.use("/api/v1/app/profile", profileAppRouter);

export default app;
