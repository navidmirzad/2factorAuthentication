import speakeasy from "speakeasy";
import qrcode from "qrcode";

export function setup2FA() {
  const secret = speakeasy.generateSecret({ name: "MyApp 2FA" });
  return {
    base32: secret.base32,
    otpauth_url: secret.otpauth_url,
  };
}

export function verify2FA(secret, token) {
  return speakeasy.totp.verify({
    secret,
    encoding: "base32",
    token,
    window: 2,
  });
}
