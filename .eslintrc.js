module.exports = {
  root: true,
  env: {
    browser: true,
    node: true,
    jest: true,
  },
  parser: "@typescript-eslint/parser",
  extends: [
    "eslint:recommended",
    "eslint-config-prettier",
    "plugin:@typescript-eslint/recommended",
  ],
  ignorePatterns: [".eslintrc.js"],
  rules: {
    "no-undef": "off",
    "@typescript-eslint/no-explicit-any": "error",
    "import/no-extraneous-dependencies": "off",
    "import/extensions": "off",
    "import/no-self-import": "off",
    "react/no-unknown-property": "off",
    "import/order": "off",
    "import/no-unresolved": "off",
    "import/no-useless-path-segments": "off",
    "import/no-duplicates": "off",
    "import/no-named-as-default": "off",
    "import/no-named-as-default-member": "off",
  },
};
