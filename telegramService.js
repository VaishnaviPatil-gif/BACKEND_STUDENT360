const axios = require("axios");

// In-memory storage for Telegram chat IDs (in production, use database)
const userTelegramIds = {};

// Get Bot Token from environment variable or .env file
const TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN;

if (!TELEGRAM_BOT_TOKEN) {
  console.warn("TELEGRAM_BOT_TOKEN not set. Telegram alerts will be skipped.");
}

const TELEGRAM_API_URL = `https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}`;

/**
 * Send alert message to a specific Telegram chat
 */
async function sendTelegramAlert(chatId, alertData) {
  if (!TELEGRAM_BOT_TOKEN) {
    console.log("[TELEGRAM] Bot token not configured. Skipping alert.");
    return false;
  }

  if (!chatId) {
    console.log("[TELEGRAM] No chat ID provided.");
    return false;
  }

  try {
    const message = formatAlertMessage(alertData);

    await axios.post(`${TELEGRAM_API_URL}/sendMessage`, {
      chat_id: chatId,
      text: message,
      parse_mode: "HTML"
    });

    console.log(`[TELEGRAM] Alert sent to chat ${chatId}: ${alertData.studentName}`);
    return true;
  } catch (error) {
    console.error(`[TELEGRAM] Failed to send alert:`, error.message);
    return false;
  }
}

/**
 * Format alert data into Telegram message
 */
function formatAlertMessage(alertData) {
  const {
    studentName = "Unknown",
    studentId = "N/A",
    class: studentClass = "N/A",
    riskLevel = "unknown",
    reason = "Health alert",
    temperature = null,
    humidity = null,
    heartRate = null,
    triggeredAt = new Date().toISOString()
  } = alertData;

  let message = `Dear Parent,\n\n`;
  message += `This is an important update from Student360.\n\n`;
  message += `<b>Alert Summary</b>\n`;
  message += `<b>Student:</b> ${studentName}\n`;
  message += `<b>ID:</b> ${studentId}\n`;
  message += `<b>Class:</b> ${studentClass}\n\n`;

  message += `<b>Risk Level:</b> `;
  message += `${riskLevel.toUpperCase()}\n`;

  message += `<b>Reason:</b> ${reason}\n\n`;

  // Add sensor data if available
  if (temperature !== null || humidity !== null || heartRate !== null) {
    message += `<b>Vital Signs:</b>\n`;
    if (temperature !== null) message += `  • Temperature: ${temperature}°C\n`;
    if (humidity !== null) message += `  • Humidity: ${humidity}%\n`;
    if (heartRate !== null) message += `  • Heart Rate: ${heartRate} BPM\n`;
    message += "\n";
  }

  message += `<b>Time:</b> ${new Date(triggeredAt).toLocaleString()}\n`;
  message += `\nPlease connect with the class teacher if you need clarification.\n`;
  message += `\n<i>Regards, Student360 Monitoring System</i>`;

  return message;
}

/**
 * Register a user's Telegram chat ID
 */
function registerUserTelegramId(userId, chatId) {
  userTelegramIds[userId] = chatId;
  console.log(`[TELEGRAM] Registered user ${userId} with chat ID ${chatId}`);
  return true;
}

/**
 * Get Telegram chat ID for a user
 */
function getUserTelegramId(userId) {
  return userTelegramIds[userId] || null;
}

/**
 * Get all registered Telegram IDs
 */
function getAllTelegramIds() {
  return { ...userTelegramIds };
}

/**
 * Send alert to all registered recipients
 */
async function broadcastAlert(alertData, recipientRoles = ["teacher", "parent"]) {
  const sentCount = { success: 0, failed: 0 };

  // In production, fetch these from database based on roles
  for (const [userId, chatId] of Object.entries(userTelegramIds)) {
    const success = await sendTelegramAlert(chatId, alertData);
    if (success) {
      sentCount.success++;
    } else {
      sentCount.failed++;
    }
  }

  return sentCount;
}

/**
 * Test Telegram connection
 */
async function testTelegramConnection() {
  if (!TELEGRAM_BOT_TOKEN) {
    return {
      success: false,
      message: "TELEGRAM_BOT_TOKEN not configured"
    };
  }

  try {
    const response = await axios.get(`${TELEGRAM_API_URL}/getMe`);
    return {
      success: true,
      botName: response.data.result.username,
      botId: response.data.result.id,
      message: `Connected to Telegram bot: @${response.data.result.username}`
    };
  } catch (error) {
    return {
      success: false,
      message: `Failed to connect: ${error.message}`
    };
  }
}

module.exports = {
  sendTelegramAlert,
  registerUserTelegramId,
  getUserTelegramId,
  getAllTelegramIds,
  broadcastAlert,
  testTelegramConnection,
  formatAlertMessage
};
