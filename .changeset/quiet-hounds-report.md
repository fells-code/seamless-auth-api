---
'seamless-auth-api': minor
---

Report an unhandled server error as 500 rather than 404.

The first error handler answered the CORS rejection and passed everything else on
with a bare `next()`. Calling `next()` with no argument from an error handler clears
the error and resumes at the next **regular** middleware, so the 500 handler directly
below it was skipped and control landed on the 404. Any unhandled exception was
therefore reported to the caller as `404 {"error":"Not Found"}`.

Two consequences beyond the wrong status:

- **Server faults were recorded against the caller.** The 404 handler logs an
  `AuthEventService.requestSuspicious` event with reason "Request to an unknown
  route." Every internal error was written into the anomaly signal the dashboard and
  the security views read, as suspicious behaviour by whoever happened to send the
  request. That stream is now free of them.
- **Real errors were easy to miss.** A 500 is alertable. A 404 on an auth API is
  background noise, and this masked a genuine regression through a full test run.

**Behaviour change:** a request that triggers an unhandled exception now answers
`500 {"error":"Internal server error"}` instead of `404 {"error":"Not Found"}`. A
genuinely unmatched route still answers 404, unchanged. Callers that retry on 5xx but
not 4xx will now retry these. No dependent needed changing: the React SDK does not
branch on 404, and the admin dashboard already maps `>= 500` to a clearer message than
the 404 text it was getting.
