module.exports = {
  root: true,
  parser: '@typescript-eslint/parser',
  parserOptions: {
    project: 'tsconfig.json',
    tsconfigRootDir: __dirname,
    sourceType: 'module',
  },
  extends: [
    'eslint:recommended',
    'eslint-config-prettier',
    'plugin:@typescript-eslint/recommended',
  ],
  ignorePatterns: ['.eslintrc.js'],
  rules: {
    'no-undef': 'off',
    '@typescript-eslint/no-explicit-any': 'error',
  },
};
