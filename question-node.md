# Security Analysis Questionnaire - Node.js / JavaScript / TypeScript

Analyze the supplied repository excerpts, applying Express/Sequelize checks only when those libraries are evidenced. Identify alternative frameworks and persistence libraries where present. API names below are retrieval hints and examples, not required implementations.

For every topic, provide conclusions, existing controls, supported findings and evidence gaps. Cite only supplied paths/lines. For findings give severity, confidence, attacker prerequisites, source-to-sink or authorization evidence, impact, remediation and a regression test. Distinguish hypotheses from confirmed code weaknesses. Missing excerpts do not prove missing controls. Do not force a finding count or claim complete coverage. Semgrep/OpenGrep rules in context are guidance unless actual scanner output is supplied; never claim they ran. A rule match alone does not establish exploitability. Use only this stack's applicable context.

## 1. Architecture, Assets and Trust Boundaries
- From package.json, app.js, server.ts, index.js, imports and configuration, identify runtime/framework versions, databases, workers, frontend and external services. Distinguish declared version ranges from resolved versions.
- Where do credentials, personal data, payment data and administrative capabilities reside? Map evidenced data flows and trust boundaries; identify encryption and key management evidence.
- Which actors, roles and tenants exist? What assets can each access, and which boundaries require authentication or authorization?

## 2. Routes, Middleware and Input Sources
- Inspect app.use, Router, app.get, app.post and route registration. Inventory only evidenced methods, endpoints, middleware order and access restrictions. Include WebSocket/message handlers if shown.
- Trace req.body, req.query, req.params, req.headers, cookies, uploads, webhook payloads and persisted user data. Where are schemas, size limits and content types enforced?
- Identify bypasses through alternate verbs, generated routes, public static paths, debug endpoints, background jobs and proxy trust settings.

## 2A. Client and Server URL, Route and Sink Inventory
- Collect URL and route evidence from both client and server code. Distinguish frontend navigation routes, outbound client API calls, backend HTTP/WebSocket endpoints, server outbound requests, redirects and static/media URLs. Report only what supplied excerpts establish; do not claim an exhaustive inventory.
- For client calls, record the source file/lines, calling component/function, HTTP method or transport, URL expression, base URL/configuration, path/query parameters, body fields and authentication mechanism. Include relative URLs and dynamic template expressions without inventing runtime hostnames or values. Redact secrets and token values.
- For server endpoints, record the route declaration file/lines, router/include/mount prefix, HTTP method, handler/controller/action, authentication/authorization and applicable middleware. Preserve unresolved prefixes and dynamic segments as unknown. Do not infer that same-looking paths are connected without registration or call evidence.
- Link each evidenced client call to its server route and handler where possible. Mark the relationship confirmed, inferred or unresolved and cite both sides. Identify server routes with no observed client caller and client calls with no observed server handler as coverage gaps, not automatically unused or exposed endpoints.
- Trace each relevant input from client field or URL parameter through the server handler to sensitive sinks: database queries, command/code execution, file access, outbound HTTP/SSRF, template rendering, HTML/DOM output and redirects. A sink is the sensitive operation consuming data, not necessarily a URL. Record sink API, file/lines, transformations, validation, authorization and any missing intermediate code.
- Also inspect client-side sinks such as innerHTML, outerHTML, insertAdjacentHTML, document.write, eval, location assignments and framework HTML bypass APIs. Establish attacker control and rendering/execution context before labeling a weakness.
- Produce a route table: Side/type | Method/transport | URL/path expression | Caller or handler | Authentication/controls | Evidence | Resolution gaps.
- Produce a separate flow table where evidence supports it: Client source/call | Server route/handler | Input field | Sink API/location | Controls | Link confidence/missing evidence. State explicitly if either side or the sink is absent from supplied excerpts.
- Retrieval targets: fetch, axios, XMLHttpRequest, HttpClient, WebSocket, EventSource, Router, Routes, routerLink, href, app.use, app.get, app.post, router.get, router.post, express.static, req.params, req.query, req.body, res.redirect and res.render. Trace nested router prefixes and frontend API base URLs. Include Angular/React/Vue routing only when those frameworks are present.

## 3. Database Injection
- Inspect sequelize.query, Sequelize.literal, query, literal, raw SQL, replacements, bind and ORM predicates. Does attacker input become query structure through concatenation or interpolation?
- Check dynamic identifiers, sort/order expressions and NoSQL operators where relevant. Distinguish bound values and safe ORM calls from unsafe construction.
- Trace a reachable input-to-query path and inspect controls before asserting injection. Provide a parameterized fix appropriate to the actual library.

## 4. Code, Commands, Templates and Deserialization
- Trace inputs into eval, Function, vm, child_process, exec, execSync, spawn and execFile, including destructured imports. Check shell options, executable selection and argument injection; process execution is not inherently vulnerable.
- Can input influence template source evaluated by EJS, Pug, Handlebars or another engine? Distinguish SSTI from unescaped output causing XSS.
- Inspect unsafe deserialization, dynamic module loading and attacker-controlled property merging for prototype pollution. Follow resulting sensitive uses rather than assuming every merge is exploitable.

## 5. Authentication, Tokens and Sessions
- Inspect login, password reset, OAuth callbacks, passport, jsonwebtoken, jwt.verify and jwt.decode where present. Are trusted identity and token validation separated correctly?
- Assess signature/key selection, allowed algorithms, expiration policy, issuer/audience where applicable, reset-token lifetime and reuse, and account enumeration.
- Inspect express-session, session stores, cookie flags, session regeneration, logout invalidation and trust proxy under the deployment model. Assess rate limits and password hashing parameters from evidence.

## 6. Authorization, Tenancy and Mass Assignment
- Trace route/router/global middleware and resource ownership predicates. Are reads, writes, deletes and administrative actions authorized server-side for each role and tenant?
- Inspect findByPk, findOne, create, update, upsert and req.body. Do explicit field lists, validation or model restrictions prevent privileged attribute changes?
- A primary-key lookup or body-to-model assignment alone is not a vulnerability. Show the reachable unauthorized operation and effective restrictions.

## 7. Browser Security, CSRF and CORS
- Inspect res.send, render, innerHTML, template escaping and sanitization. Does attacker data reach an executable browser context? Account for response Content-Type and contextual encoding.
- Inspect helmet, CSP and headers set by application or infrastructure. Absence of a named package does not establish absence of protection.
- For automatically attached browser credentials, evaluate CSRF tokens, Origin checks, SameSite and state-changing GET routes. Inspect cors origin/credentials: distinguish arbitrary credentialed origin reflection from a literal wildcard rejected for credentialed browser reads.

## 8. Files, Uploads, Outbound Requests and Redirects
- Trace input into sendFile, download, readFile, writeFile, multer and archive extraction. Check path containment, symlinks, ownership, upload limits and public serving behavior.
- Inspect fetch, axios, http.request and https.request for attacker-controlled destinations, redirects, schemes and internal-network access. Identify the deployment assumptions needed to establish SSRF.
- Inspect res.redirect and return URLs for destination validation and sensitive-data leakage.

## 9. Business Logic, Availability and Background Work
- Are prices, quantities, discounts, balances and workflow transitions derived and validated server-side? Inspect transaction boundaries, idempotency and concurrent updates.
- Inspect rate limiting, parser/upload limits, expensive regexes, synchronous operations, queue consumers and retry behavior for evidenced resource-exhaustion paths.
- Are webhooks authenticated and replay-resistant? Are job payloads and WebSocket actions authorized at the point of use?

## 10. Secrets, Configuration, Logging and Dependencies
- Inspect process.env, configuration, crypto, password hashing, logs and error handlers. Assess secret strength/lifecycle, redaction, production stack traces and audit events; do not reproduce secret values.
- Determine environment-specific TLS, proxy, debug and storage settings. Distinguish application controls from unknown infrastructure controls.
- Identify dependency review gaps. Package ranges alone cannot prove a resolved vulnerable version or reachable CVE. Use supplied lockfiles/advisory evidence only; juice2.py excludes several lockfiles. Do not invent external lookups.

## 10A. Hardcoded Passwords and Secrets
- Inspect supplied code, configuration, deployment files and client assets for literal passwords, API/access tokens, database credentials/URLs, JWT/session signing secrets, encryption keys, private keys and insecure default/fallback credentials. Include fixtures and test data, but distinguish placeholders and intentional examples from plausible active credentials.
- For each candidate, report only redacted type, source path/lines, apparent purpose, runtime usage and confidence. Never reproduce complete secret values or attempt to validate credentials against external services.
- Determine whether the value reaches authentication, signing, encryption or another sensitive operation and whether it is client-exposed. Recommend removal, secure provisioning and rotation/revocation when appropriate. Do not claim repository-wide absence from selected excerpts; identify omitted files and unresolved usage. Review the selected snapshot only, not Git history.
## 11. Risk, Remediation and Verification
- For risks evidenced in this topic's supplied excerpts, prioritize by impact, reachability and attacker prerequisites. Do not assume access to findings from earlier independently analyzed sections.
- Propose specific fixes and positive/negative regression cases, including unauthorized users and cross-tenant requests. Separate SAST, dependency scanning and integration tests by what each verifies.
- State which callers, middleware, templates, configuration or resolved dependencies must be inspected next. Citation availability does not prove finding correctness.


