module.exports = {
  root: true,
  env: { node: true, es2020: true },
  parser: "@typescript-eslint/parser",
  plugins: ["@typescript-eslint"],
  extends: ["eslint:recommended", "plugin:@typescript-eslint/recommended"],
  ignorePatterns: ["lib/**"],
  rules: {
    "max-len": "off",
    "require-jsdoc": "off",
    "object-curly-spacing": "off",
    "brace-style": "off",
    "block-spacing": "off",
    "no-multi-spaces": "off"
  }
};
