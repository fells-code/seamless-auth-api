---
'seamless-auth-api': patch
---

Self-service account recovery codes are stronger and their guesses are counted per account. Email codes are now six letters, like the sign-in code, and phone codes are eight digits. Each account may spend ten wrong recovery codes per channel in any 24 hours, counted across every `/recovery/start` and kept in the database. Once the budget is spent, `/recovery/start` sends no code and `/recovery/verify` checks none until the oldest wrong code is 24 hours old. Both answer as they otherwise would (`200` and `401 invalid_recovery_code`). The budget is separate for each channel and does not affect sign-in lockout or recovery codes. If it cannot be read, the channel is treated as spent.
