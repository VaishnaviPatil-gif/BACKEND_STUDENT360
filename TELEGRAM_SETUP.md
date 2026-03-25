# Student360 Telegram Alerts Setup Guide

## Overview
This integration enables sending real-time alerts via Telegram when students have health anomalies detected by the IoT monitoring system.

## Getting Started

### Step 1: Create a Telegram Bot
1. Open Telegram and search for **@BotFather**
2. Click /start and then select /newbot
3. Give your bot a name (e.g., "Student360 Alerts")
4. Give it a unique username (e.g., "student360_alerts_bot")
5. BotFather will give you a **Bot Token** - save this!

Example token format: `1234567890:ABCDefgh_ijklmnopqrstuvwxyz`

### Step 2: Configure Environment Variable
1. Create or edit `.env` file in the project root
2. Add your bot token:
```env
TELEGRAM_BOT_TOKEN=1234567890:ABCDefgh_ijklmnopqrstuvwxyz
```

### Step 3: Install Dependencies
```bash
npm install
```

### Step 4: Start the Server
```bash
node server.js
```

### Step 5: Get Your Chat ID
To receive alerts, you need your Telegram chat ID:

**Method A: Using the API**
1. Start a chat with your bot on Telegram
2. Message your bot anything
3. Call this endpoint:
```bash
curl "http://localhost:3000/api/telegram/test"
```

**Method B: Manually**
1. Open Telegram and go to your bot
2. Send any message
3. Visit: `https://api.telegram.org/bot<YOUR_BOT_TOKEN>/getUpdates`
4. Replace `<YOUR_BOT_TOKEN>` with your actual token
5. Look for `"chat":{"id":XXXXX}` - that's your Chat ID

### Step 6: Register for Alerts
Once you have your chat ID, register it with the backend:

```bash
curl -X POST http://localhost:3000/api/telegram/register \
  -H "Content-Type: application/json" \
  -d '{"userId": "teacher_1", "chatId": "YOUR_CHAT_ID"}'
```

Example:
```bash
curl -X POST http://localhost:3000/api/telegram/register \
  -H "Content-Type: application/json" \
  -d '{"userId": "teacher_1", "chatId": "123456789"}'
```

### Step 7: Test the Integration
```bash
curl -X POST http://localhost:3000/api/alert \
  -H "Content-Type: application/json" \
  -d '{
    "studentId": 1,
    "reason": "Critical health reading detected",
    "riskLevel": "high"
  }'
```

You should receive a formatted Telegram alert!

---

## API Endpoints

### POST /api/alert
Trigger an alert for a student (automatically sends Telegram notifications).

**Request:**
```json
{
  "studentId": 1,
  "reason": "High heart rate detected",
  "riskLevel": "high"
}
```

**Response:**
```json
{
  "success": true,
  "message": "Alert triggered successfully.",
  "alert": {
    "id": 1,
    "studentId": 1,
    "studentName": "Aarav Patel",
    "class": "10-A",
    "riskLevel": "high",
    "reason": "High heart rate detected",
    "triggeredAt": "2026-03-24T10:45:30Z",
    "temperature": 37.2,
    "humidity": 65,
    "heartRate": 125
  },
  "telegramNotifications": {
    "sent": 2,
    "failed": 0
  }
}
```

### POST /api/telegram/register
Register a user (teacher, parent, etc.) to receive Telegram alerts.

**Request:**
```json
{
  "userId": "teacher_1",
  "chatId": "123456789"
}
```

### GET /api/telegram/users
Get all registered Telegram users.

**Response:**
```json
{
  "success": true,
  "count": 2,
  "users": {
    "teacher_1": "123456789",
    "parent_1": "987654321"
  }
}
```

### GET /api/telegram/test
Test Telegram bot connection.

**Response (Success):**
```json
{
  "success": true,
  "botName": "student360_alerts_bot",
  "botId": 1234567890,
  "message": "Connected to Telegram bot: @student360_alerts_bot"
}
```

### GET /api/alert/history
Get alert history.

**Response:**
```json
{
  "success": true,
  "count": 5,
  "alerts": [...]
}
```

---

## Features

✅ **Real-time Alerts** - Instantly notified when students have health anomalies  
✅ **Rich Formatting** - Color-coded risk levels (🔴 High, 🟡 Medium, 🟢 Low)  
✅ **Sensor Data** - Includes temperature, humidity, and heart rate in alerts  
✅ **Broadcast Alerts** - Send to multiple teachers/parents simultaneously  
✅ **Alert History** - Track all alerts triggered  
✅ **Easy Registration** - Simple API to add new alert recipients  

---

## Troubleshooting

### No alerts received?
1. Verify `TELEGRAM_BOT_TOKEN` is set correctly in `.env`
2. Test bot connection: `GET /api/telegram/test`
3. Ensure you've registered your chat ID: `GET /api/telegram/users`
4. Check server logs for errors

### "TELEGRAM_BOT_TOKEN not set" warning?
Add the token to your `.env` file and restart the server.

### Wrong chat ID?
1. Start a chat with your bot on Telegram
2. Send any message
3. Call `GET /api/telegram/test` - it will show incoming messages
4. Find your chat ID in the response

### Rate limiting?
Telegram has rate limits. If you send too many alerts quickly, some may be delayed.

---

## Frontend Integration

To integrate alerts into your HTML frontend:

```javascript
// Register user for alerts
async function registerTelegramAlerts(userId, chatId) {
  const response = await fetch('http://localhost:3000/api/telegram/register', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ userId, chatId })
  });
  return response.json();
}

// Trigger alert
async function triggerAlert(studentId, reason) {
  const response = await fetch('http://localhost:3000/api/alert', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      studentId,
      reason,
      riskLevel: 'high'
    })
  });
  return response.json();
}
```

---

## Security Notes

⚠️ **Important:**
- Keep your `TELEGRAM_BOT_TOKEN` secret (don't commit `.env` to git)
- Use `.env.example` as a template for team members
- In production, use a proper database instead of in-memory storage for Telegram IDs
- Add authentication to Telegram registration endpoints
- Rate limit the `/api/alert` endpoint to prevent abuse

---

## Next Steps

1. ✅ Set up Telegram bot and token
2. ✅ Configure environment variables
3. ✅ Register users for alerts
4. 🔄 Integrate into HTML dashboard
5. 🔄 Add database persistence for chat IDs
6. 🔄 Set up alert rules/thresholds
