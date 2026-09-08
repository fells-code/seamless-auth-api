---
'seamless-auth-api': patch
---

Fix four defects found in a review of `src`, all of them in how the service is
configured and started rather than in how it authenticates.

**The container healthcheck asks the port the server was told to use.** It probed a
hardcoded 5312 while `server.ts` binds `process.env.PORT`, and `.env.example` invites an
operator to set that variable. Setting it to anything else left the probe hitting a closed
port, so Docker marked the container unhealthy and an orchestrator restarted it, in a loop,
while the API served correctly.

**`magic_link_redirect_uris` can be set from the environment.** It was the one system config
key with no entry in `SYSTEM_CONFIG_ENV_MAP`, so the only control over where a magic link may
send someone could not be set at deploy time and had to be applied through the admin API
after every fresh install. It now has a variable, a parser and a default, and a test asserts
the map covers every key the schema defines, so the next key added upstream is caught here
rather than by an operator who cannot configure it.

**`/health/version` stops reading `package.json` on every request.** The value cannot change
while the process runs, and that endpoint takes no authentication, so each caller was paying
for a synchronous file read and a parse on the event loop. It is read once, and resolved
relative to the module rather than `process.cwd()`, which is not the repository root for a
process started elsewhere.

**The model loader filters on real extensions.** Its test asked whether each file ended with
its own extension, which is always true, so it excluded `index` and nothing else: every other
file in the directory was imported and required to default export a model initialiser.
Nothing broke only because the build emits no declarations or source maps. Turning either on,
or adding a shared types file next to the models, would have failed startup with an error
naming the file but not the reason.
