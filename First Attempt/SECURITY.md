# Security Setup Guide

## API Keys Configuration

### 1. Create Environment Variables
Create a `.env` file in the backend directory with your API keys:

```bash
# Gemini API Keys - DO NOT COMMIT THIS FILE TO VERSION CONTROL
GEMINI_API_KEY_1=your_primary_gemini_api_key_here
GEMINI_API_KEY_2=your_backup_gemini_api_key_here

# ZAP API Key (if needed)
ZAP_API_KEY=your_zap_api_key_here
```

### 2. Install python-dotenv
```bash
pip install python-dotenv
```

### 3. Update app.py to load environment variables
Add this to the top of `app.py`:
```python
from dotenv import load_dotenv
load_dotenv()
```

## Security Features Implemented

### ✅ Backend Proxy
- API keys are stored server-side only
- Frontend never sees API keys
- Automatic key switching on rate limits

### ✅ Rate Limiting
- 10 requests per minute per IP
- Prevents abuse and quota exhaustion

### ✅ Error Handling
- Graceful degradation when API keys fail
- User-friendly error messages
- No sensitive information leaked

### ✅ Input Validation
- All user inputs validated
- XSS prevention
- Secure file handling

## Production Deployment

### 1. Environment Variables
- Use your hosting platform's environment variable system
- Never hardcode API keys in production

### 2. HTTPS
- Always use HTTPS in production
- Configure SSL certificates

### 3. CORS
- Restrict CORS to your domain only
- Don't use `CORS(app)` in production

### 4. Rate Limiting
- Consider using Redis for distributed rate limiting
- Monitor API usage and adjust limits

## Current API Keys (Development)
- Primary: AIzaSyCoMLa_u8vwimOnUQXRpK0Y7sIcZyw86Ys
- Backup: AIzaSyCCjynIUn0M-diwZa6gsHL7uPW1i6cBaSc

**⚠️ WARNING: These keys are for development only. Use your own keys in production!** 