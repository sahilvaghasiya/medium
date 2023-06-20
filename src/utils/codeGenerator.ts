export const generateOTP = (n: number): string => {
  const digits = '1234567890';
  let otp = '';

  for (let i = 0; i < n; i++) {
    otp += digits[Math.floor(Math.random() * digits.length)];
  }
  return otp;
};

export const generateOTPCode = (n: number): string => {
  const digits = '1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  let otpCode = '';

  for (let i = 0; i < n; i++) {
    otpCode += digits[Math.floor(Math.random() * digits.length)];
  }
  return otpCode;
};

export const invitationCode = (n: number): string => {
  const digits = '1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  let otpCode = '';

  for (let i = 0; i < n; i++) {
    otpCode += digits[Math.floor(Math.random() * digits.length)];
  }
  return otpCode;
};
