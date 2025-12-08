const express = require('express');
const fs = require('fs');
const path = require('path');
const cors = require('cors');
const app = express();
const PORT = process.env.PORT || 4000;
const BASE_PATH = '/mock';

app.use(cors());
app.use(express.json());

const configPath = path.join(__dirname, 'IHFA_Mock_API_Secure.json');
const { endpoints } = JSON.parse(fs.readFileSync(configPath, 'utf-8'));

app.use((req, res, next) => {
  const delay = parseInt(process.env.MOCK_DELAY_MS || '0', 10);
  if (delay > 0) setTimeout(next, delay);
  else next();
});

function hasValidAuth(def, req) {
  if (def.headers && def.headers.Authorization) {
    const auth = req.headers['authorization'];
    if (!auth || !auth.startsWith('Bearer ')) {
      return false;
    }
  }
  return true;
}

/**
 * Default handler: just enforces Authorization and returns JSON success.
 */
function buildHandler(def) {
  return (req, res) => {
    if (!hasValidAuth(def, req)) {
      return res.status(401).json({
        status: false,
        message: 'Missing or invalid Authorization header',
        data: null
      });
    }

    if (def.response) return res.json(def.response);

    return res.json({
      status: true,
      message: 'Mock endpoint reached',
      data: {
        method: req.method,
        path: req.path,
        body: req.body,
        query: req.query
      }
    });
  };
}

/**
 * /auth/token
 * - authenticationKey missing or 'invalid' => error
 * - anything else => success
 */
function tokenHandler(def) {
  return (req, res) => {
    const { authenticationKey } = req.body || {};
    if (!authenticationKey || authenticationKey === 'invalid') {
      return res.json({
        status: false,
        message: 'Invalid authentication key.',
        data: null
      });
    }
    return res.json(def.response);
  };
}

/**
 * /auth/login
 * - only the username/password from JSON are accepted
 * - all other combinations => invalid credentials
 */
function loginHandler(def) {
  const validUsername = def.request && def.request.username;
  const validPassword = def.request && def.request.password;

  return (req, res) => {
    if (!hasValidAuth(def, req)) {
      return res.status(401).json({
        status: false,
        message: 'Missing or invalid Authorization header',
        data: null
      });
    }

    const { username, password } = req.body || {};

    if (username === validUsername && password === validPassword) {
      return res.json(def.response);
    }

    return res.json({
      status: false,
      message: 'Invalid username or password.',
      data: null
    });
  };
}

/**
 * /auth/forgot-username
 * - emailId must match JSON request.emailId => success
 * - invalid format => "Enter a valid email address."
 * - other email => "No account found..."
 */
function forgotUsernameHandler(def) {
  const expectedEmail = def.request && def.request.emailId;

  return (req, res) => {
    if (!hasValidAuth(def, req)) {
      return res.status(401).json({
        status: false,
        message: 'Missing or invalid Authorization header',
        data: null
      });
    }

    const { emailId } = req.body || {};

    if (!emailId || typeof emailId !== 'string' || !emailId.includes('@')) {
      return res.json({
        status: false,
        message: 'Please enter a valid email address.',
        data: null
      });
    }

    if (emailId !== expectedEmail) {
      return res.json({
        status: false,
        message: 'No account found for the entered email.',
        data: null
      });
    }

    return res.json(def.response);
  };
}

/**
 * /auth/forgot-password/request
 * Same pattern as forgot-username.
 */
function forgotPasswordRequestHandler(def) {
  const expectedEmail = def.request && def.request.emailId;

  return (req, res) => {
    if (!hasValidAuth(def, req)) {
      return res.status(401).json({
        status: false,
        message: 'Missing or invalid Authorization header',
        data: null
      });
    }

    const { emailId } = req.body || {};

    if (!emailId || typeof emailId !== 'string' || !emailId.includes('@')) {
      return res.json({
        status: false,
        message: 'Please enter a valid email address.',
        data: null
      });
    }

    if (emailId !== expectedEmail) {
      return res.json({
        status: false,
        message: 'No account found for the entered email.',
        data: null
      });
    }

    return res.json(def.response);
  };
}

/**
 * /auth/forgot-password/validate
 * - otp and otpReferenceId must match JSON request
 * - otp === "000000" => expired
 * - wrong otp => invalid
 * - wrong ref => invalid/expired session
 */
function forgotPasswordValidateHandler(def) {
  const expectedOtp = def.request && def.request.otp;
  const expectedRef = def.request && def.request.otpReferenceId;

  return (req, res) => {
    if (!hasValidAuth(def, req)) {
      return res.status(401).json({
        status: false,
        message: 'Missing or invalid Authorization header',
        data: null
      });
    }

    const { otp, otpReferenceId } = req.body || {};

    if (!otp || !otpReferenceId) {
      return res.json({
        status: false,
        message: 'OTP and reference id are required.',
        data: null
      });
    }

    if (otpReferenceId !== expectedRef) {
      return res.json({
        status: false,
        message: 'Invalid or expired OTP session.',
        data: null
      });
    }

    if (otp === expectedOtp) {
      return res.json(def.response);
    }

    if (otp === '000000') {
      return res.json({
        status: false,
        message: 'OTP has expired. Please request a new one.',
        data: null
      });
    }

    return res.json({
      status: false,
      message: 'Invalid OTP.',
      data: null
    });
  };
}

/**
 * /auth/forgot-password/reset
 * - validation-request-id must match JSON
 * - newPassword === confirmPassword
 */
function forgotPasswordResetHandler(def) {
  const expectedValidationId =
    def.request && def.request['validation-request-id'];

  return (req, res) => {
    if (!hasValidAuth(def, req)) {
      return res.status(401).json({
        status: false,
        message: 'Missing or invalid Authorization header',
        data: null
      });
    }

    const {
      newPassword,
      confirmPassword,
      ['validation-request-id']: validationId
    } = req.body || {};

    if (!validationId || validationId !== expectedValidationId) {
      return res.json({
        status: false,
        message: 'Invalid or expired reset session.',
        data: null
      });
    }

    if (!newPassword || !confirmPassword) {
      return res.json({
        status: false,
        message: 'New Password and Confirm Password are required.',
        data: null
      });
    }

    if (newPassword !== confirmPassword) {
      return res.json({
        status: false,
        message: 'Password and Confirm Password should match.',
        data: null
      });
    }

    return res.json(def.response);
  };
}

/**
 * /registration/validate-user
 * - loanNumber, ssnLast4, zipCode must all match JSON
 */
function validateUserHandler(def) {
  const expected = def.request || {};

  return (req, res) => {
    if (!hasValidAuth(def, req)) {
      return res.status(401).json({
        status: false,
        message: 'Missing or invalid Authorization header',
        data: null
      });
    }

    const { loanNumber, ssnLast4, zipCode } = req.body || {};

    if (!loanNumber || !ssnLast4 || !zipCode) {
      return res.json({
        status: false,
        message: 'Loan number, SSN last 4, and ZIP code are required.',
        data: null
      });
    }

    if (loanNumber !== expected.loanNumber) {
      return res.json({
        status: false,
        message: 'Loan number not found.',
        data: null
      });
    }

    if (ssnLast4 !== expected.ssnLast4) {
      return res.json({
        status: false,
        message: 'SSN does not match our records.',
        data: null
      });
    }

    if (zipCode !== expected.zipCode) {
      return res.json({
        status: false,
        message: 'ZIP code does not match our records.',
        data: null
      });
    }

    return res.json(def.response);
  };
}

/**
 * /registration/create-account
 * - registrationid must match JSON
 * - password === confirmPassword
 */
function createAccountHandler(def) {
  const expected = def.request || {};

  return (req, res) => {
    if (!hasValidAuth(def, req)) {
      return res.status(401).json({
        status: false,
        message: 'Missing or invalid Authorization header',
        data: null
      });
    }

    const {
      registrationid,
      firstName,
      lastName,
      emailAddress,
      phoneNumber,
      password,
      confirmPassword
    } = req.body || {};

    if (!registrationid || registrationid !== expected.registrationid) {
      return res.json({
        status: false,
        message: 'Invalid or expired registration session.',
        data: null
      });
    }

    if (!password || !confirmPassword) {
      return res.json({
        status: false,
        message: 'Password and Confirm Password are required.',
        data: null
      });
    }

    if (password !== confirmPassword) {
      return res.json({
        status: false,
        message: 'Password and Confirm Password should match.',
        data: null
      });
    }

    // Could add extra checks (email/phone mismatch) if needed later
    return res.json(def.response);
  };
}

/**
 * /registration/email-verification
 * - email must match JSON
 */
function emailVerificationHandler(def) {
  const expected = def.request || {};

  return (req, res) => {
    if (!hasValidAuth(def, req)) {
      return res.status(401).json({
        status: false,
        message: 'Missing or invalid Authorization header',
        data: null
      });
    }

    const { email } = req.body || {};

    if (!email) {
      return res.json({
        status: false,
        message: 'Email is required for verification.',
        data: null
      });
    }

    if (email !== expected.email) {
      return res.json({
        status: false,
        message: 'Verification link is invalid or expired.',
        data: null
      });
    }

    return res.json(def.response);
  };
}

/**
 * /registration/otp/request
 * - deliveryMethod must be SMS, Call, or SMS/Call
 */
function registrationOtpRequestHandler(def) {
  return (req, res) => {
    if (!hasValidAuth(def, req)) {
      return res.status(401).json({
        status: false,
        message: 'Missing or invalid Authorization header',
        data: null
      });
    }

    const { deliveryMethod } = req.body || {};
    if (!deliveryMethod) {
      return res.json({
        status: false,
        message: 'Delivery method is required.',
        data: null
      });
    }

    const normalized = String(deliveryMethod).toLowerCase();
    if (
      !['sms', 'call', 'sms/call', 'sms or call'].includes(normalized)
    ) {
      return res.json({
        status: false,
        message: 'Unsupported delivery method. Please choose SMS or Call.',
        data: null
      });
    }

    return res.json(def.response);
  };
}

/**
 * /registration/otp/validate
 * Same style as forgot-password/validate.
 */
function registrationOtpValidateHandler(def) {
  const expectedOtp = def.request && def.request.otp;
  const expectedRef = def.request && def.request.otpReferenceId;

  return (req, res) => {
    if (!hasValidAuth(def, req)) {
      return res.status(401).json({
        status: false,
        message: 'Missing or invalid Authorization header',
        data: null
      });
    }

    const { otp, otpReferenceId } = req.body || {};

    if (!otp || !otpReferenceId) {
      return res.json({
        status: false,
        message: 'OTP and reference id are required.',
        data: null
      });
    }

    if (otpReferenceId !== expectedRef) {
      return res.json({
        status: false,
        message: 'Invalid or expired OTP session.',
        data: null
      });
    }

    if (otp === expectedOtp) {
      return res.json(def.response);
    }

    if (otp === '000000') {
      return res.json({
        status: false,
        message: 'OTP has expired. Please request a new one.',
        data: null
      });
    }

    return res.json({
      status: false,
      message: 'Invalid OTP.',
      data: null
    });
  };
}

/**
 * /legal/terms-privacy
 * - acceptTermsAndPrivacy must be true
 */
function legalHandler(def) {
  return (req, res) => {
    if (!hasValidAuth(def, req)) {
      return res.status(401).json({
        status: false,
        message: 'Missing or invalid Authorization header',
        data: null
      });
    }

    const { acceptTermsAndPrivacy } = req.body || {};

    if (acceptTermsAndPrivacy !== true) {
      return res.json({
        status: false,
        message: 'You must accept Terms and Privacy Policy to continue.',
        data: null
      });
    }

    return res.json(def.response);
  };
}

/**
 * /refinance
 * - userId must match JSON
 * - basic validation on modeofcontact
 */
function refinanceHandler(def) {
  const expected = def.request || {};

  return (req, res) => {
    if (!hasValidAuth(def, req)) {
      return res.status(401).json({
        status: false,
        message: 'Missing or invalid Authorization header',
        data: null
      });
    }

    const {
      userId,
      firstName,
      lastName,
      emailAddress,
      phoneNumber,
      prefferedtime,
      modeofcontact
    } = req.body || {};

    if (!userId || userId !== expected.userId) {
      return res.json({
        status: false,
        message: 'User is not eligible for refinance or invalid user.',
        data: null
      });
    }

    if (!modeofcontact) {
      return res.json({
        status: false,
        message: 'Preferred mode of contact is required.',
        data: null
      });
    }

    const normalized = String(modeofcontact).toLowerCase();
    if (
      !['email', 'call', 'email/call', 'email or call'].includes(normalized)
    ) {
      return res.json({
        status: false,
        message: 'Preferred mode of contact is not supported.',
        data: null
      });
    }

    return res.json(def.response);
  };
}

/**
 * /auth/refresh
 * - refreshToken must match JSON request.refreshToken
 */
function refreshHandler(def) {
  const expected = def.request || {};

  return (req, res) => {
    if (!hasValidAuth(def, req)) {
      return res.status(401).json({
        status: false,
        message: 'Missing or invalid Authorization header',
        data: null
      });
    }

    const { refreshToken } = req.body || {};

    if (!refreshToken || refreshToken !== expected.refreshToken) {
      return res.json({
        status: false,
        message: 'Invalid or expired refresh token.',
        data: null
      });
    }

    return res.json(def.response);
  };
}

/**
 * /__health
 * - Do NOT enforce Authorization; just return health.
 */
function healthHandler(def) {
  return (req, res) => {
    return res.json(def.response || { status: 'ok', time: new Date().toISOString() });
  };
}

// Register endpoints with specific handlers
Object.entries(endpoints).forEach(([route, def]) => {
  const method = (def.method || 'GET').toLowerCase();
  const fullPath = `${BASE_PATH}${route}`;

  if (!['get', 'post', 'put', 'patch', 'delete'].includes(method)) {
    console.warn(`Unsupported method for ${route}: ${def.method}`);
    return;
  }

  let handler;

  switch (route) {
    case '/auth/token':
      handler = tokenHandler(def);
      console.log(`Registered (TOKEN) ${method.toUpperCase()} ${fullPath}`);
      break;
    case '/auth/login':
      handler = loginHandler(def);
      console.log(`Registered (LOGIN) ${method.toUpperCase()} ${fullPath}`);
      break;
    case '/auth/forgot-username':
      handler = forgotUsernameHandler(def);
      console.log(`Registered (FORGOT USERNAME) ${method.toUpperCase()} ${fullPath}`);
      break;
    case '/auth/forgot-password/request':
      handler = forgotPasswordRequestHandler(def);
      console.log(`Registered (FORGOT PW REQUEST) ${method.toUpperCase()} ${fullPath}`);
      break;
    case '/auth/forgot-password/validate':
      handler = forgotPasswordValidateHandler(def);
      console.log(`Registered (FORGOT PW VALIDATE) ${method.toUpperCase()} ${fullPath}`);
      break;
    case '/auth/forgot-password/reset':
      handler = forgotPasswordResetHandler(def);
      console.log(`Registered (FORGOT PW RESET) ${method.toUpperCase()} ${fullPath}`);
      break;
    case '/registration/validate-user':
      handler = validateUserHandler(def);
      console.log(`Registered (REG VALIDATE USER) ${method.toUpperCase()} ${fullPath}`);
      break;
    case '/registration/create-account':
      handler = createAccountHandler(def);
      console.log(`Registered (REG CREATE ACCOUNT) ${method.toUpperCase()} ${fullPath}`);
      break;
    case '/registration/email-verification':
      handler = emailVerificationHandler(def);
      console.log(`Registered (REG EMAIL VERIFY) ${method.toUpperCase()} ${fullPath}`);
      break;
    case '/registration/otp/request':
      handler = registrationOtpRequestHandler(def);
      console.log(`Registered (REG OTP REQUEST) ${method.toUpperCase()} ${fullPath}`);
      break;
    case '/registration/otp/validate':
      handler = registrationOtpValidateHandler(def);
      console.log(`Registered (REG OTP VALIDATE) ${method.toUpperCase()} ${fullPath}`);
      break;
    case '/legal/terms-privacy':
      handler = legalHandler(def);
      console.log(`Registered (LEGAL TERMS) ${method.toUpperCase()} ${fullPath}`);
      break;
    case '/refinance':
      handler = refinanceHandler(def);
      console.log(`Registered (REFINANCE) ${method.toUpperCase()} ${fullPath}`);
      break;
    case '/auth/refresh':
      handler = refreshHandler(def);
      console.log(`Registered (REFRESH) ${method.toUpperCase()} ${fullPath}`);
      break;
    case '/__health':
      handler = healthHandler(def);
      console.log(`Registered (HEALTH) ${method.toUpperCase()} ${fullPath}`);
      break;
    default:
      handler = buildHandler(def);
      console.log(`Registered ${method.toUpperCase()} ${fullPath}`);
  }

  app[method](fullPath, handler);
});

app.get('/', (req, res) => {
  res.json({
    message: 'IHFA Mock API Server',
    baseUrl: `http://localhost:${PORT}${BASE_PATH}`
  });
});

app.listen(PORT, () => {
  console.log(`Mock server running on http://localhost:${PORT}${BASE_PATH}`);
});
