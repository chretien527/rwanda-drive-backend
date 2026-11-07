# Email Configuration Guide

This application supports two methods for sending emails (OTP verification, password resets, etc.):

1. **Resend API** (Recommended)
2. **SMTP** (Fallback)

## Using Resend (Recommended)

### Why Resend?
- Simple API-based email delivery
- Better deliverability rates
- No complex SMTP configuration
- Built-in analytics and monitoring
- More reliable than SMTP

### Setup Steps

1. **Create a Resend Account**
   - Go to [resend.com](https://resend.com)
   - Sign up for a free account
   - Verify your email address

2. **Get Your API Key**
   - Log in to your Resend dashboard
   - Navigate to **API Keys** section
   - Click **Create API Key**
   - Copy your API key (starts with `re_`)

3. **Configure Domain (Important for Production)**
   - In Resend dashboard, go to **Domains**
   - Click **Add Domain**
   - Enter your domain (e.g., `yourdomain.com`)
   - Add the DNS records shown to your domain provider
   - Wait for verification (usually takes a few minutes)

4. **Update Environment Variables**
   ```bash
   RESEND_API_KEY=re_your_actual_api_key_here
   SMTP_FROM_EMAIL=noreply@yourdomain.com
   SMTP_FROM_NAME=Rwanda Drive
   ```

5. **Test Your Configuration**
   - Start your application
   - Try registering a new user
   - Check if the OTP email arrives
   - Check Resend dashboard for email logs

### Development vs Production

**Development (no domain):**
- You can use Resend's test mode with `onboarding@resend.dev` as the from address
- Emails will only be delivered to your verified email address
- Set: `SMTP_FROM_EMAIL=onboarding@resend.dev`

**Production (with custom domain):**
- Use your verified domain: `SMTP_FROM_EMAIL=noreply@yourdomain.com`
- Emails can be sent to any recipient
- Better deliverability and branding

## Using SMTP (Fallback)

If you don't configure Resend, the system falls back to SMTP.

### Gmail Setup

1. **Enable 2-Factor Authentication**
   - Go to [myaccount.google.com/security](https://myaccount.google.com/security)
   - Enable 2-Step Verification

2. **Create App Password**
   - Go to [myaccount.google.com/apppasswords](https://myaccount.google.com/apppasswords)
   - Select "Mail" and your device
   - Copy the 16-character password

3. **Update Environment Variables**
   ```bash
   SMTP_HOST=smtp.gmail.com
   SMTP_PORT=587
   SMTP_USERNAME=your-email@gmail.com
   SMTP_PASSWORD="your-16-char-app-password"
   SMTP_FROM_EMAIL=your-email@gmail.com
   SMTP_FROM_NAME=Rwanda Drive
   ```

### Other SMTP Providers

For other providers (SendGrid, Mailgun, etc.), update:
```bash
SMTP_HOST=smtp.yourprovider.com
SMTP_PORT=587
SMTP_USERNAME=your-username
SMTP_PASSWORD=your-password
```

## How the System Chooses

The application automatically selects the email method:

1. **If `RESEND_API_KEY` is set** → Uses Resend (preferred)
2. **Else if SMTP credentials are set** → Uses SMTP
3. **Else** → Logs OTP to console (development only)

## Troubleshooting

### Resend Issues

**"API Key Invalid"**
- Verify your API key starts with `re_`
- Make sure there are no extra spaces
- Check that the key wasn't revoked in the dashboard

**"Domain Not Verified"**
- For production, ensure your domain is verified in Resend
- Check DNS records are properly configured
- Use `onboarding@resend.dev` for testing

**"Rate Limited"**
- Free tier has sending limits
- Upgrade your plan if needed
- Check Resend dashboard for current usage

### SMTP Issues

**"Authentication Failed"**
- Gmail: Ensure you're using an App Password, not your regular password
- Check that 2FA is enabled
- Verify username/password have no extra spaces

**"Connection Timeout"**
- Check firewall settings
- Verify port 587 is open
- Try port 465 with `SMTP_PORT=465`

**"From Address Mismatch" (Gmail)**
- Gmail requires the `SMTP_FROM_EMAIL` to match your Gmail address
- Set both to the same email

### Development Mode

If neither Resend nor SMTP is configured:
```bash
# Application will log OTPs to console
==================================================
🔑 DEV VERIFICATION OTP for user@example.com: 123456
==================================================
```

This is useful for local development without email setup.

## Security Best Practices

1. **Never commit API keys or passwords**
   - Use `.env` file (already in `.gitignore`)
   - Use environment variables in production
   - Rotate keys regularly

2. **Use different keys for different environments**
   - Development key for testing
   - Production key with domain verification

3. **Monitor email logs**
   - Check Resend dashboard regularly
   - Set up alerts for failures
   - Review bounce rates

## Cost Considerations

### Resend Pricing (as of 2024)
- **Free Tier**: 3,000 emails/month
- **Pro**: $20/month for 50,000 emails
- Good for most applications

### SMTP (Gmail)
- Free for personal use
- Limited to ~500 emails/day
- May have deliverability issues for bulk sending

For production applications, **Resend is strongly recommended** over SMTP.
