require("dotenv").config();

const express = require("express");
const cors = require("cors");
const {  
  sendTelegramAlert,
  registerUserTelegramId,
  getUserTelegramId,
  getAllTelegramIds,
  broadcastAlert,
  testTelegramConnection
} = require("./telegramService");

const app = express();
const PORT = 3000;
const HOST = "0.0.0.0";

// Allow frontend HTML pages (or any local client) to call this API.
app.use(cors());
app.use(express.json());

// Simple in-memory storage for latest IoT reading (no database).
let latestSensorData = null;

// JSON-style student data you can edit anytime.
const students = [
  { id: 1, name: "Aarav Patel", class: "10-A", riskLevel: "low" },
  { id: 2, name: "Diya Sharma", class: "10-A", riskLevel: "medium" },
  { id: 3, name: "Rohan Verma", class: "10-B", riskLevel: "high" },
  { id: 4, name: "Meera Nair", class: "9-C", riskLevel: "low" },
  { id: 5, name: "Ananya Reddy", class: "10-B", riskLevel: "low" },
  { id: 6, name: "Kiran Kumar", class: "10-C", riskLevel: "medium" },
  { id: 7, name: "Priya Menon", class: "9-A", riskLevel: "low" },
  { id: 8, name: "Siddharth Rao", class: "9-B", riskLevel: "medium" },
  { id: 9, name: "Ishita Gupta", class: "11-A", riskLevel: "low" },
  { id: 10, name: "Vikram Singh", class: "11-A", riskLevel: "high" },
  { id: 11, name: "Nisha Iyer", class: "11-B", riskLevel: "medium" },
  { id: 12, name: "Rahul Das", class: "11-C", riskLevel: "low" },
  { id: 13, name: "Kavya Jain", class: "12-A", riskLevel: "medium" },
  { id: 14, name: "Aditya Kulkarni", class: "12-A", riskLevel: "high" },
  { id: 15, name: "Pooja Desai", class: "12-B", riskLevel: "low" },
  { id: 16, name: "Arjun Nair", class: "12-B", riskLevel: "medium" },
  { id: 17, name: "Sneha Verma", class: "9-C", riskLevel: "low" },
  { id: 18, name: "Yashwanth R", class: "10-C", riskLevel: "medium" },
  { id: 19, name: "Madhuri P", class: "10-A", riskLevel: "low" },
  { id: 20, name: "Tanvi S", class: "11-B", riskLevel: "high" },
  { id: 21, name: "Harsha Vardhan", class: "11-C", riskLevel: "medium" },
  { id: 22, name: "Lavanya K", class: "12-C", riskLevel: "low" },
  { id: 23, name: "Ritesh Chawla", class: "12-C", riskLevel: "medium" },
  { id: 24, name: "Meghana S", class: "9-A", riskLevel: "low" },
  { id: 25, name: "Sagarika T", class: "9-B", riskLevel: "high" },
  { id: 26, name: "Naveen A", class: "10-B", riskLevel: "medium" },
  { id: 27, name: "Deepika R", class: "10-C", riskLevel: "low" },
  { id: 28, name: "Bhavya M", class: "11-A", riskLevel: "medium" },
  { id: 29, name: "Rohan K", class: "12-A", riskLevel: "high" },
  { id: 30, name: "Keerthi L", class: "12-B", riskLevel: "low" }
];

// Keep alert history in memory so frontend can confirm alerts were triggered.
const alertHistory = [];
const parentTelegramByStudentId = {};

app.get("/", (req, res) => {
  res.json({
    success: true,
    message: "Student360 backend is running.",
    endpoints: {
      receiveIotData: "POST /api",
      latestSensorData: "GET /api/latest",
      students: "GET /api/students",
      triggerAlert: "POST /api/alert",
      triggerParentAlert: "POST /api/alert/parent",
      registerTelegram: "POST /api/telegram/register",
      getTelegramIds: "GET /api/telegram/users",
      testTelegram: "GET /api/telegram/test",
      alertHistory: "GET /api/alert/history"
    }
  });
});

// POST /api -> receive IoT sensor data from NodeMCU.
app.post("/api", (req, res) => {
  // Accept both standard keys and common short keys from IoT firmware.
  const temperature = req.body.temperature ?? req.body.temp;
  const humidity = req.body.humidity ?? req.body.hum;
  const heartRate = req.body.heartRate ?? req.body.bpm;

  // Basic validation to keep data clean.
  if (
    temperature === undefined ||
    humidity === undefined ||
    heartRate === undefined
  ) {
    return res.status(400).json({
      success: false,
      message: "temperature, humidity, and heartRate are required."
    });
  }

  latestSensorData = {
    temperature: Number(temperature),
    humidity: Number(humidity),
    heartRate: Number(heartRate),
    receivedAt: new Date().toISOString()
  };

  console.log("[IOT DATA RECEIVED]", latestSensorData);

  res.status(200).json({
    success: true,
    message: "Sensor data received successfully.",
    data: latestSensorData
  });
});

// GET /api/latest -> return latest IoT sensor reading.
app.get("/api/latest", (req, res) => {
  if (!latestSensorData) {
    return res.status(404).json({
      success: false,
      message: "No sensor data available yet."
    });
  }

  res.json({
    success: true,
    temperature: latestSensorData.temperature,
    humidity: latestSensorData.humidity,
    heartRate: latestSensorData.heartRate,
    receivedAt: latestSensorData.receivedAt,
    data: latestSensorData
  });
});

// GET /api/students -> return list of students.
app.get("/api/students", (req, res) => {
  res.json({
    success: true,
    count: students.length,
    data: students
  });
});

// POST /api/alert/parent -> send alert to one specific parent.
app.post("/api/alert/parent", async (req, res) => {
  const {
    parentUserId,
    studentId,
    className,
    reason = "Teacher alert",
    riskLevel = "high"
  } = req.body;

  if (!studentId) {
    return res.status(400).json({
      success: false,
      message: "studentId is required."
    });
  }

  const student = students.find((s) => s.id === Number(studentId));
  if (!student) {
    return res.status(404).json({
      success: false,
      message: "Student not found."
    });
  }

  const mappedParent = parentTelegramByStudentId[String(studentId)] || null;
  const resolvedParentUserId = parentUserId || mappedParent?.userId;
  const parentChatId =
    (resolvedParentUserId ? getUserTelegramId(resolvedParentUserId) : null) ||
    mappedParent?.chatId ||
    null;

  if (!parentChatId) {
    return res.status(404).json({
      success: false,
      message: "Parent Telegram chat ID not found for this student. Ask parent to register from Parent dashboard first."
    });
  }

  const alertRecord = {
    id: alertHistory.length + 1,
    studentId: student.id,
    studentName: student.name,
    class: className || student.class,
    riskLevel,
    reason,
    targetParent: resolvedParentUserId || "registered-parent",
    triggeredAt: new Date().toISOString(),
    temperature: latestSensorData?.temperature || null,
    humidity: latestSensorData?.humidity || null,
    heartRate: latestSensorData?.heartRate || null
  };

  alertHistory.push(alertRecord);

  const sent = await sendTelegramAlert(parentChatId, alertRecord);
  if (!sent) {
    return res.status(502).json({
      success: false,
      message: "Unable to send Telegram alert to the selected parent."
    });
  }

  res.status(200).json({
    success: true,
    message: "Telegram alert sent to parent successfully.",
    alert: alertRecord,
    recipient: {
      parentUserId: resolvedParentUserId || null,
      chatId: parentChatId
    }
  });
});

// POST /api/alert -> trigger high-risk alert.
app.post("/api/alert", async (req, res) => {
  const { studentId, reason = "High-risk behavior detected", riskLevel = "high" } = req.body;

  if (!studentId) {
    return res.status(400).json({
      success: false,
      message: "studentId is required to trigger an alert."
    });
  }

  const student = students.find((s) => s.id === Number(studentId));

  if (!student) {
    return res.status(404).json({
      success: false,
      message: "Student not found."
    });
  }

  const alertRecord = {
    id: alertHistory.length + 1,
    studentId: student.id,
    studentName: student.name,
    class: student.class,
    riskLevel,
    reason,
    triggeredAt: new Date().toISOString(),
    temperature: latestSensorData?.temperature || null,
    humidity: latestSensorData?.humidity || null,
    heartRate: latestSensorData?.heartRate || null
  };

  alertHistory.push(alertRecord);

  console.log("[ALERT TRIGGERED]", alertRecord);

  // Send Telegram alerts to all registered users
  const telegramResult = await broadcastAlert(alertRecord);
  console.log(`[TELEGRAM] Alert sent to ${telegramResult.success} recipients (${telegramResult.failed} failed)`);

  res.status(200).json({
    success: true,
    message: "Alert triggered successfully.",
    alert: alertRecord,
    telegramNotifications: {
      sent: telegramResult.success,
      failed: telegramResult.failed
    }
  });
});

// POST /api/telegram/register -> register user for Telegram alerts
app.post("/api/telegram/register", (req, res) => {
  const { userId, chatId, studentId, parentEmail } = req.body;

  if (!chatId) {
    return res.status(400).json({
      success: false,
      message: "chatId is required."
    });
  }

  const sanitizedEmail = (parentEmail || "").trim().toLowerCase();
  const emailBasedUserId = sanitizedEmail ? `parent_${sanitizedEmail}` : "";
  const resolvedUserId = userId || emailBasedUserId || `parent_${studentId || Date.now()}`;

  registerUserTelegramId(resolvedUserId, chatId);

  if (studentId) {
    parentTelegramByStudentId[String(studentId)] = {
      userId: resolvedUserId,
      chatId
    };
  }

  res.status(200).json({
    success: true,
    message: `Telegram registration saved with chat ID ${chatId}.`,
    registration: {
      userId: resolvedUserId,
      studentId: studentId || null,
      chatId
    }
  });
});

// GET /api/telegram/users -> get all registered Telegram users
app.get("/api/telegram/users", (req, res) => {
  const allIds = getAllTelegramIds();
  res.json({
    success: true,
    count: Object.keys(allIds).length,
    users: allIds
  });
});

// GET /api/telegram/test -> test Telegram bot connection
app.get("/api/telegram/test", async (req, res) => {
  const result = await testTelegramConnection();
  const statusCode = result.success ? 200 : 400;
  res.status(statusCode).json(result);
});

// GET /api/alert/history -> get alert history
app.get("/api/alert/history", (req, res) => {
  res.json({
    success: true,
    count: alertHistory.length,
    alerts: alertHistory
  });
});

app.listen(PORT, HOST, () => {
  console.log(`Student360 backend running at http://${HOST}:${PORT}`);
  console.log("CORS enabled: frontend pages can call this API.");
  console.log("Telegram integration ready.");
  console.log("Set TELEGRAM_BOT_TOKEN environment variable to enable alerts.");
});
