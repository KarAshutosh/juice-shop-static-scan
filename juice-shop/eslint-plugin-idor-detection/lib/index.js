// eslint-plugin-idor-detection/lib/index.js
module.exports = {
  rules: {
    "direct-database-access": require("./rules/direct-database-access"),
    "file-access": require("./rules/file-access"),
    "predictable-ids": require("./rules/predictable-ids"),
    "missing-object-authorization": require("./rules/missing-object-authorization"),
    "mass-assignment": require("./rules/mass-assignment"),
    "unprotected-profile": require("./rules/unprotected-profile"),
    "detect-missing-auth-check": require("./rules/detect-missing-auth-check"),
    "detect-unsafe-parameter-usage": require("./rules/detect-unsafe-parameter-usage"),
    "detect-hardcoded-user-id": require("./rules/detect-hardcoded-user-id")
  },
  configs: {
    recommended: {
      plugins: ["idor-detection"],
      rules: {
        "idor-detection/direct-database-access": "error",
        "idor-detection/file-access": "error",
        "idor-detection/predictable-ids": "error",
        "idor-detection/missing-object-authorization": "error",
        "idor-detection/mass-assignment": "error",
        "idor-detection/unprotected-profile": "error",
        "idor-detection/detect-missing-auth-check": "error",
        "idor-detection/detect-unsafe-parameter-usage": "error",
        "idor-detection/detect-hardcoded-user-id": "error"
      }
    }
  }
};