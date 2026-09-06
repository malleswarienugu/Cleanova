const express = require("express");
const mysql = require("mysql2/promise");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
require("dotenv").config();

const app = express();

const PORT = process.env.PORT || 5000;

const JWT_SECRET =
    process.env.JWT_SECRET || "Cleanova-development-secret";


// ============================================================
// BASIC MIDDLEWARE
// ============================================================

app.use(cors());

app.use(express.json());

app.use(express.urlencoded({ extended: true }));


// ============================================================
// UPLOADS FOLDER
// ============================================================

const uploadsDirectory = path.join(__dirname, "uploads");

if (!fs.existsSync(uploadsDirectory)) {
    fs.mkdirSync(uploadsDirectory, { recursive: true });
}


// Make uploaded images publicly accessible
app.use(
    "/uploads",
    express.static(uploadsDirectory)
);


// ============================================================
// MULTER PHOTO UPLOAD
// ============================================================

const storage = multer.diskStorage({

    destination: function (req, file, cb) {
        cb(null, uploadsDirectory);
    },

    filename: function (req, file, cb) {

        const extension =
            path.extname(file.originalname).toLowerCase();

        const uniqueName =
            "report-" +
            Date.now() +
            "-" +
            Math.round(Math.random() * 1000000) +
            extension;

        cb(null, uniqueName);
    }

});


const upload = multer({

    storage: storage,

    limits: {
        fileSize: 5 * 1024 * 1024
    },

    fileFilter: function (req, file, cb) {

        const allowedTypes = [
            "image/jpeg",
            "image/png",
            "image/webp",
            "image/jpg"
        ];

        if (!allowedTypes.includes(file.mimetype)) {

            return cb(
                new Error(
                    "Only JPG, PNG and WEBP images are allowed."
                )
            );

        }

        cb(null, true);
    }

});


// ============================================================
// MYSQL CONNECTION POOL
// ============================================================

const db = mysql.createPool({
    host: process.env.DB_HOST || "localhost",
    port: Number(process.env.DB_PORT) || 3306,
    user: process.env.DB_USER || "root",
    password: process.env.DB_PASSWORD || "",
    database: process.env.DB_NAME || "Cleanova",

    ssl: process.env.DB_SSL === "true"
        ? { rejectUnauthorized: false }
        : undefined,

    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});


// ============================================================
// TEST DATABASE CONNECTION
// ============================================================

async function testDatabase() {

    try {

        const connection = await db.getConnection();

        console.log("MySQL database connected successfully.");

        connection.release();

    } catch (error) {

        console.error(
            "MySQL connection failed:",
            error.message
        );

    }

}


// ============================================================
// HEALTH CHECK
// ============================================================

app.get("/", (req, res) => {

    res.json({
        success: true,
        message: "Cleanova backend is running."
    });

});


app.get("/api/health", async (req, res) => {

    try {

        await db.query("SELECT 1");

        res.json({
            success: true,
            message: "Cleanova API and MySQL are connected."
        });

    } catch (error) {

        res.status(500).json({
            success: false,
            message: "Database connection failed.",
            error: error.message
        });

    }

});


// ============================================================
// AUTHENTICATION MIDDLEWARE
// ============================================================

function authenticate(req, res, next) {

    try {

        const authorization =
            req.headers.authorization || "";

        if (!authorization.startsWith("Bearer ")) {

            return res.status(401).json({
                success: false,
                message: "Authentication required."
            });

        }

        const token =
            authorization.substring(7);

        const decoded =
            jwt.verify(token, JWT_SECRET);

        req.user = decoded;

        next();

    } catch (error) {

        return res.status(401).json({
            success: false,
            message: "Invalid or expired login session."
        });

    }

}


// ============================================================
// ADMIN AUTHORIZATION
// ============================================================

function requireAdmin(req, res, next) {

    if (!req.user || req.user.role !== "ADMIN") {

        return res.status(403).json({
            success: false,
            message: "Admin access required."
        });

    }

    next();
}



// ============================================================
// ADMIN - VIEW ALL REPORTS
// ============================================================

app.get("/api/admin/reports", authenticate, requireAdmin, async (req, res) => {

    try {

        const [reports] = await db.query(`
            SELECT
                r.id,
                r.report_code,
                r.user_id,
                r.waste_type,
                r.quantity,
                r.severity,
                r.description,
                r.latitude,
                r.longitude,
                r.photo_url,
                r.status,
                r.admin_note,
                r.created_at,
                r.updated_at,
                u.name AS reporter_name,
                u.email AS reporter_email
            FROM reports r
            INNER JOIN users u ON r.user_id = u.id
            ORDER BY r.created_at DESC
        `);

        res.json({
            success: true,
            reports
        });

    } catch (error) {

        console.error("Admin reports error:", error);

        res.status(500).json({
            success: false,
            message: "Failed to load admin reports."
        });

    }

});


// ============================================================
// ADMIN - UPDATE REPORT STATUS
// ============================================================

app.patch("/api/admin/reports/:id/status", authenticate, requireAdmin, async (req, res) => {

    try {

        const reportId = Number(req.params.id);

        const { status, adminNote } = req.body;

        const allowedStatuses = [
            "Pending",
            "In Progress",
            "Verified",
            "Rejected"
        ];

        if (!allowedStatuses.includes(status)) {

            return res.status(400).json({
                success: false,
                message: "Invalid report status."
            });

        }

        const [result] = await db.query(
            `
            UPDATE reports
            SET
                status = ?,
                admin_note = ?
            WHERE id = ?
            `,
            [
                status,
                adminNote || null,
                reportId
            ]
        );

        if (result.affectedRows === 0) {

            return res.status(404).json({
                success: false,
                message: "Report not found."
            });

        }

        res.json({
            success: true,
            message: "Report status updated successfully."
        });

    } catch (error) {

        console.error("Admin status update error:", error);

        res.status(500).json({
            success: false,
            message: "Failed to update report status."
        });

    }

});

// =========================
// CLEANUP TRACKING
// =========================

// Create a cleanup for a report
app.post("/api/admin/cleanups", authenticate, requireAdmin, async (req, res) => {

    try {

        const {
            reportId,
            assignedTo,
            adminNote
        } = req.body;

        if(!reportId){
            return res.status(400).json({
                success: false,
                message: "Report ID is required."
            });
        }

        // Check that report exists
        const [reports] = await db.query(
            `
            SELECT id
            FROM reports
            WHERE id = ?
            `,
            [Number(reportId)]
        );

        if(reports.length === 0){
            return res.status(404).json({
                success: false,
                message: "Report not found."
            });
        }

        // Prevent duplicate active cleanup
        const [existing] = await db.query(
            `
            SELECT id
            FROM cleanups
            WHERE report_id = ?
            AND status <> 'Verified'
            LIMIT 1
            `,
            [Number(reportId)]
        );

        if(existing.length > 0){
            return res.status(409).json({
                success: false,
                message: "A cleanup already exists for this report."
            });
        }

        const [result] = await db.query(
            `
            INSERT INTO cleanups
            (
                report_id,
                assigned_to,
                status,
                admin_note
            )
            VALUES (?, ?, 'Assigned', ?)
            `,
            [
                Number(reportId),
                assignedTo ? Number(assignedTo) : null,
                adminNote || null
            ]
        );

        // Move report into cleanup stage
        await db.query(
            `
            UPDATE reports
            SET status = 'In Progress'
            WHERE id = ?
            `,
            [Number(reportId)]
        );

        res.json({
            success: true,
            message: "Cleanup created successfully.",
            cleanupId: result.insertId
        });

    } catch(error) {

        console.error("Create cleanup error:", error);

        res.status(500).json({
            success: false,
            message: "Failed to create cleanup."
        });

    }

});


// Get all cleanups for admin
app.get("/api/admin/cleanups", authenticate, requireAdmin, async (req, res) => {

    try {

        const [cleanups] = await db.query(
            `
            SELECT
                c.id,
                c.report_id,
                c.assigned_to,
                c.before_photo_url,
                c.after_photo_url,
                c.plastic_collected,
                c.status,
                c.admin_note,
                c.created_at,
                c.updated_at,

                r.report_code,
                r.waste_type,
                r.quantity,
                r.severity,

                u.name AS assigned_name,
                u.email AS assigned_email

            FROM cleanups c

            INNER JOIN reports r
                ON c.report_id = r.id

            LEFT JOIN users u
                ON c.assigned_to = u.id

            ORDER BY c.created_at DESC
            `
        );

        res.json({
            success: true,
            cleanups
        });

    } catch(error) {

        console.error("Admin cleanups error:", error);

        res.status(500).json({
            success: false,
            message: "Failed to load cleanups."
        });

    }

});
app.patch("/api/admin/cleanups/:id/status", authenticate, requireAdmin, async (req, res) => {
    try {
        const cleanupId = Number(req.params.id);
        const { status } = req.body;

        const allowedStatuses = [
            "Assigned",
            "In Progress",
            "Completed",
            "Verified"
        ];

        if (!allowedStatuses.includes(status)) {
            return res.status(400).json({
                success: false,
                message: "Invalid cleanup status."
            });
        }

        const [cleanups] = await db.query(
            `SELECT id, report_id
             FROM cleanups
             WHERE id = ?`,
            [cleanupId]
        );

        if (cleanups.length === 0) {
            return res.status(404).json({
                success: false,
                message: "Cleanup task not found."
            });
        }

        const reportId = cleanups[0].report_id;

        await db.query(
            `UPDATE cleanups
             SET status = ?
             WHERE id = ?`,
            [status, cleanupId]
        );

        // Keep the related report status synchronized
        let reportStatus = "In Progress";

        if (status === "Completed" || status === "Verified") {
            reportStatus = "Verified";
        }

        await db.query(
            `UPDATE reports
             SET status = ?
             WHERE id = ?`,
            [reportStatus, reportId]
        );

        res.json({
            success: true,
            message: "Cleanup status updated successfully."
        });

    } catch (error) {
        console.error("Cleanup status update error:", error);

        res.status(500).json({
            success: false,
            message: "Failed to update cleanup status."
        });
    }
});

// Get cleanups assigned to the logged-in user
app.get("/api/my-cleanups", authenticate, async (req, res) => {

    try {

        const [cleanups] = await db.query(
            `
            SELECT
                c.id,
                c.report_id,
                c.before_photo_url,
                c.after_photo_url,
                c.plastic_collected,
                c.status,
                c.admin_note,
                c.created_at,
                c.updated_at,

                r.report_code,
                r.waste_type,
                r.quantity,
                r.severity

            FROM cleanups c

            INNER JOIN reports r
                ON c.report_id = r.id

            WHERE c.assigned_to = ?

            ORDER BY c.created_at DESC
            `,
            [req.user.id]
        );

        res.json({
            success: true,
            cleanups
        });

    } catch(error) {

        console.error("My cleanups error:", error);

        res.status(500).json({
            success: false,
            message: "Failed to load your cleanup activity."
        });

    }

});

// ============================================================
// REGISTER
// ============================================================

app.post("/api/auth/register", async (req, res) => {

    try {

        const {
            name,
            email,
            password
        } = req.body;

        if (!name || !email || !password) {

            return res.status(400).json({
                success: false,
                message: "Name, email and password are required."
            });

        }

        const cleanName =
            String(name).trim();

        const cleanEmail =
            String(email).trim().toLowerCase();

        if (cleanName.length < 2) {

            return res.status(400).json({
                success: false,
                message: "Please enter a valid name."
            });

        }

        if (password.length < 6) {

            return res.status(400).json({
                success: false,
                message: "Password must contain at least 6 characters."
            });

        }


        const [existingUsers] = await db.query(
            "SELECT id FROM users WHERE email = ? LIMIT 1",
            [cleanEmail]
        );


        if (existingUsers.length > 0) {

            return res.status(409).json({
                success: false,
                message: "An account with this email already exists."
            });

        }


        const passwordHash =
            await bcrypt.hash(password, 10);


        const [result] = await db.query(

            `INSERT INTO users
            (name, email, password_hash)
            VALUES (?, ?, ?)`,

            [
                cleanName,
                cleanEmail,
                passwordHash
            ]

        );


        res.status(201).json({

            success: true,

            message: "Account created successfully.",

            user: {
                id: result.insertId,
                name: cleanName,
                email: cleanEmail,
                points: 0,
                reports_count: 0,
                cleanups_count: 0,
                plastic_collected: 0,
                role: "USER"
            }

        });

    } catch (error) {

        console.error(
            "Registration error:",
            error
        );

        res.status(500).json({
            success: false,
            message: "Registration failed."
        });

    }

});


// ============================================================
// LOGIN
// ============================================================

app.post("/api/auth/login", async (req, res) => {

    try {

        const {
            email,
            password
        } = req.body;

        if (!email || !password) {

            return res.status(400).json({
                success: false,
                message: "Email and password are required."
            });

        }


        const cleanEmail =
            String(email).trim().toLowerCase();


        const [users] = await db.query(

            `SELECT
                id,
                name,
                email,
                password_hash,
                points,
                reports_count,
                cleanups_count,
                plastic_collected,
                role
             FROM users
             WHERE email = ?
             LIMIT 1`,

            [cleanEmail]

        );


        if (users.length === 0) {

            return res.status(401).json({
                success: false,
                message: "Invalid email or password."
            });

        }


        const user = users[0];


        const passwordMatches =
            await bcrypt.compare(
                password,
                user.password_hash
            );


        if (!passwordMatches) {

            return res.status(401).json({
                success: false,
                message: "Invalid email or password."
            });

        }


        const token =
            jwt.sign(

                {
                    id: user.id,
                    email: user.email,
                    role: user.role
                },

                JWT_SECRET,

                {
                    expiresIn: "7d"
                }

            );


        res.json({

            success: true,

            token,

            user: {

                id: user.id,
                name: user.name,
                email: user.email,
                points: user.points,
                reports_count: user.reports_count,
                cleanups_count: user.cleanups_count,
                plastic_collected: user.plastic_collected,
                role: user.role

            }

        });

    } catch (error) {

        console.error(
            "Login error:",
            error
        );

        res.status(500).json({
            success: false,
            message: "Login failed."
        });

    }

});


// ============================================================
// CURRENT USER
// ============================================================

app.get("/api/auth/me", authenticate, async (req, res) => {

    try {

        const [users] = await db.query(

            `SELECT
                id,
                name,
                email,
                points,
                reports_count,
                cleanups_count,
                plastic_collected,
                role
             FROM users
             WHERE id = ?
             LIMIT 1`,

            [req.user.id]

        );


        if (users.length === 0) {

            return res.status(404).json({
                success: false,
                message: "User not found."
            });

        }


        res.json({

            success: true,

            user: users[0]

        });

    } catch (error) {

        console.error(
            "Auth/me error:",
            error
        );

        res.status(500).json({
            success: false,
            message: "Unable to load user."
        });

    }

});


// ============================================================
// CREATE WASTE REPORT
// ============================================================

app.post(
    "/api/reports",
    authenticate,
    upload.single("photo"),
    async (req, res) => {

        let connection;

        try {

            const {
                wasteType,
                quantity,
                severity,
                description,
                latitude,
                longitude
            } = req.body;


            // ------------------------------------------------
            // VALIDATION
            // ------------------------------------------------

            if (
                !wasteType ||
                !quantity ||
                !severity ||
                !description ||
                latitude === undefined ||
                longitude === undefined
            ) {

                return res.status(400).json({

                    success: false,

                    message:
                        "Please provide all required report information."

                });

            }


            const validQuantities = [
                "Small",
                "Medium",
                "Large"
            ];


            const validSeverities = [
                "Low",
                "Medium",
                "High"
            ];


            if (!validQuantities.includes(quantity)) {

                return res.status(400).json({

                    success: false,

                    message:
                        "Invalid quantity selected."

                });

            }


            if (!validSeverities.includes(severity)) {

                return res.status(400).json({

                    success: false,

                    message:
                        "Invalid severity selected."

                });

            }


            const lat =
                Number(latitude);

            const lng =
                Number(longitude);


            if (
                !Number.isFinite(lat) ||
                !Number.isFinite(lng) ||
                lat < -90 ||
                lat > 90 ||
                lng < -180 ||
                lng > 180
            ) {

                return res.status(400).json({

                    success: false,

                    message:
                        "Invalid GPS coordinates."

                });

            }


            // ------------------------------------------------
            // PHOTO
            // ------------------------------------------------

            let photoUrl = null;


            if (req.file) {

                photoUrl =
                    `/uploads/${req.file.filename}`;

            }


            // ------------------------------------------------
            // GENERATE REPORT CODE
            // ------------------------------------------------

            const [latestReports] = await db.query(

                `SELECT report_code
                 FROM reports
                 ORDER BY id DESC
                 LIMIT 1`

            );


            let nextNumber = 1001;


            if (latestReports.length > 0) {

                const lastCode =
                    latestReports[0].report_code;

                const number =
                    parseInt(
                        String(lastCode).replace(/\D/g, ""),
                        10
                    );

                if (!Number.isNaN(number)) {

                    nextNumber =
                        Math.max(
                            1000,
                            number
                        ) + 1;

                }

            }


            const reportCode =
                `CB${nextNumber}`;


            // ------------------------------------------------
            // DATABASE TRANSACTION
            // ------------------------------------------------

            connection =
                await db.getConnection();


            await connection.beginTransaction();


            // Insert report
            const [reportResult] =
                await connection.query(

                    `INSERT INTO reports
                    (
                        report_code,
                        user_id,
                        waste_type,
                        quantity,
                        severity,
                        description,
                        latitude,
                        longitude,
                        photo_url,
                        status
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'Pending')`,

                    [

                        reportCode,

                        req.user.id,

                        wasteType,

                        quantity,

                        severity,

                        description,

                        lat,

                        lng,

                        photoUrl

                    ]

                );


            const reportId =
                reportResult.insertId;


            // ------------------------------------------------
            // AWARD 10 POINTS
            // ------------------------------------------------

            await connection.query(

                `UPDATE users
                 SET
                    points = points + 10,
                    reports_count = reports_count + 1
                 WHERE id = ?`,

                [req.user.id]

            );


            // Record point history
            await connection.query(

                `INSERT INTO points_history
                (
                    user_id,
                    report_id,
                    points,
                    reason
                )
                VALUES (?, ?, ?, ?)`,

                [

                    req.user.id,

                    reportId,

                    10,

                    "Waste report submitted"

                ]

            );


            await connection.commit();


            // ------------------------------------------------
            // SUCCESS RESPONSE
            // ------------------------------------------------

            res.status(201).json({

                success: true,

                message:
                    "Waste report submitted successfully.",

                reportCode,

                reportId,

                pointsAwarded: 10,

                status: "Pending",

                photoUrl

            });


        } catch (error) {


            if (connection) {

                try {

                    await connection.rollback();

                } catch (rollbackError) {

                    console.error(
                        "Rollback error:",
                        rollbackError
                    );

                }

            }


            // Delete uploaded file if database failed
            if (req.file) {

                try {

                    fs.unlinkSync(
                        path.join(
                            uploadsDirectory,
                            req.file.filename
                        )
                    );

                } catch (fileError) {

                    console.error(
                        "Uploaded file cleanup error:",
                        fileError
                    );

                }

            }


            console.error(
                "Report submission error:",
                error
            );


            res.status(500).json({

                success: false,

                message:
                    "Unable to submit the waste report.",

                error:
                    error.message

            });


        } finally {

            if (connection) {

                connection.release();

            }

        }

    }
);


// ============================================================
// GET ALL REPORTS
// ============================================================

app.get("/api/reports", async (req, res) => {

    try {

        const [reports] = await db.query(

            `SELECT
                r.id,
                r.report_code,
                r.user_id,
                r.waste_type,
                r.quantity,
                r.severity,
                r.description,
                r.latitude,
                r.longitude,
                r.photo_url,
                r.status,
                r.admin_note,
                r.created_at,
                r.updated_at,
                u.name AS reporter_name
             FROM reports r
             INNER JOIN users u
                 ON r.user_id = u.id
             ORDER BY r.created_at DESC`

        );


        res.json({

            success: true,

            reports

        });

    } catch (error) {

        console.error(
            "Get reports error:",
            error
        );

        res.status(500).json({

            success: false,

            message:
                "Unable to load reports."

        });

    }

});

// =========================
// MY REPORTS
// =========================

app.get("/api/my-reports", authenticate, async (req, res) => {

    try {

        const [reports] = await db.query(`
            SELECT
                r.id,
                r.report_code,
                r.waste_type,
                r.quantity,
                r.severity,
                r.description,
                r.latitude,
                r.longitude,
                r.photo_url,
                r.status,
                r.admin_note,
                r.created_at,
                r.updated_at
            FROM reports r
            WHERE r.user_id = ?
            ORDER BY r.created_at DESC
        `, [req.user.id]);

        res.json({
            success: true,
            reports
        });

    } catch (error) {

        console.error("My reports error:", error);

        res.status(500).json({
            success: false,
            message: "Failed to load your reports."
        });

    }

});

// ============================================================
// COMMUNITY MEMBERS COUNT
// ============================================================

app.get("/api/users/count", async (req, res) => {

    try {

        const [rows] = await db.query(
            "SELECT COUNT(*) AS totalUsers FROM users"
        );

        res.json({
            success: true,
            totalUsers: rows[0].totalUsers
        });

    } catch (error) {

        console.error(
            "User count error:",
            error
        );

        res.status(500).json({
            success: false,
            message: "Failed to get user count."
        });

    }

});


// ============================================================
// COMPLETED CLEANUPS COUNT
// ============================================================

app.get("/api/cleanups/count", async (req, res) => {

    try {

        const [rows] = await db.query(`
            SELECT COUNT(*) AS completedCleanups
            FROM cleanups
            WHERE status = 'Completed'
        `);

        res.json({
            success: true,
            completedCleanups: rows[0].completedCleanups
        });

    } catch (error) {

        console.error(
            "Cleanup count error:",
            error
        );

        res.status(500).json({
            success: false,
            message: "Failed to get cleanup count."
        });

    }

});

// ============================================================
// LEADERBOARD
// ============================================================

app.get(
    "/api/leaderboard",
    authenticate,
    async (req, res) => {

        try {

            const [users] = await db.query(

                `SELECT
                    id,
                    name,
                    points,
                    reports_count,
                    cleanups_count,
                    plastic_collected
                 FROM users
                 ORDER BY points DESC, reports_count DESC, name ASC
                 LIMIT 50`

            );


            res.json({

                success: true,

                leaderboard: users

            });

        } catch (error) {

            console.error(
                "Leaderboard error:",
                error
            );

            res.status(500).json({

                success: false,

                message:
                    "Unable to load leaderboard."

            });

        }

    }
);


// ============================================================
// ERROR HANDLER
// ============================================================

app.use((error, req, res, next) => {

    console.error(
        "Server error:",
        error
    );


    if (
        error instanceof multer.MulterError
    ) {

        if (
            error.code === "LIMIT_FILE_SIZE"
        ) {

            return res.status(400).json({

                success: false,

                message:
                    "Photo is too large. Maximum size is 5 MB."

            });

        }

    }


    res.status(500).json({

        success: false,

        message:
            error.message ||
            "Something went wrong."

    });

});


// ============================================================
// START SERVER
// ============================================================

async function startServer() {

    await testDatabase();


    app.listen(
        PORT,
        () => {

            console.log("");
            console.log("========================================");
            console.log("       Cleanova BACKEND");
            console.log("========================================");
            console.log(
                `Server running: http://localhost:${PORT}`
            );
            console.log(
                `API: http://localhost:${PORT}/api`
            );
            console.log(
                `Uploads: http://localhost:${PORT}/uploads`
            );
            console.log("========================================");
            console.log("");

        }
    );

}


startServer();
