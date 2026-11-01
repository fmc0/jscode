# Security Analysis Questionnaire - Ruby / Ruby on Rails

Analyze the supplied repository excerpts. Confirm Rails and its version; apply Devise, Pundit, CanCanCan, Active Storage and other package checks only when present. API names below are retrieval hints and examples, not required implementations.

For every topic, provide conclusions, existing controls, supported findings and evidence gaps. Cite only supplied paths/lines. For findings give severity, confidence, attacker prerequisites, source-to-sink or authorization evidence, impact, remediation and a regression test. Distinguish hypotheses from confirmed code weaknesses. Missing excerpts do not prove missing controls. Do not force a finding count or claim complete coverage. Semgrep/OpenGrep rules in context are guidance unless actual scanner output is supplied; never claim they ran. A rule match alone does not establish exploitability. Ignore rules for unrelated stacks.

## 1. Architecture, Assets and Trust Boundaries
- Inspect Gemfile, gem specifications, config/application.rb, config/environments, initializers and application classes. Identify Rails/runtime versions, databases, caches, jobs and external services; distinguish declared ranges from resolved versions.
- Locate credentials, personal data and administrative capabilities. Map evidenced browser/controller/model/database/job/storage trust boundaries and encryption/key-management controls.
- Identify users, roles, tenants and service identities, including API-only components and mounted engines.

## 2. Routes, Filters and Input Sources
- Inspect config/routes.rb, resources, namespace, mount, controllers, before_action and skip_before_action. Inventory only evidenced endpoints, verbs and restrictions.
- Trace params, request headers/body, cookies, uploads, webhook data and persisted user input. Locate parsing, permitted fields and size/type limits.
- Check custom actions, alternate verbs, mounted dashboards, Action Cable channels and background entry points where shown. Trace inherited filters and exemptions.

## 2A. Client and Server URL, Route and Sink Inventory
- Collect URL and route evidence from both client and server code. Distinguish frontend navigation routes, outbound client API calls, backend HTTP/WebSocket endpoints, server outbound requests, redirects and static/media URLs. Report only what supplied excerpts establish; do not claim an exhaustive inventory.
- For client calls, record the source file/lines, calling component/function, HTTP method or transport, URL expression, base URL/configuration, path/query parameters, body fields and authentication mechanism. Include relative URLs and dynamic template expressions without inventing runtime hostnames or values. Redact secrets and token values.
- For server endpoints, record the route declaration file/lines, router/include/mount prefix, HTTP method, handler/controller/action, authentication/authorization and applicable middleware. Preserve unresolved prefixes and dynamic segments as unknown. Do not infer that same-looking paths are connected without registration or call evidence.
- Link each evidenced client call to its server route and handler where possible. Mark the relationship confirmed, inferred or unresolved and cite both sides. Identify server routes with no observed client caller and client calls with no observed server handler as coverage gaps, not automatically unused or exposed endpoints.
- Trace each relevant input from client field or URL parameter through the server handler to sensitive sinks: database queries, command/code execution, file access, outbound HTTP/SSRF, template rendering, HTML/DOM output and redirects. A sink is the sensitive operation consuming data, not necessarily a URL. Record sink API, file/lines, transformations, validation, authorization and any missing intermediate code.
- Also inspect client-side sinks such as innerHTML, outerHTML, insertAdjacentHTML, document.write, eval, location assignments and framework HTML bypass APIs. Establish attacker control and rendering/execution context before labeling a weakness.
- Produce a route table: Side/type | Method/transport | URL/path expression | Caller or handler | Authentication/controls | Evidence | Resolution gaps.
- Produce a separate flow table where evidence supports it: Client source/call | Server route/handler | Input field | Sink API/location | Controls | Link confidence/missing evidence. State explicitly if either side or the sink is absent from supplied excerpts.
- Retrieval targets: routes.rb, resources, resource, namespace, scope, mount, match, get, post, controller actions, url_for, link_to, button_to, form_with, redirect_to, render, fetch, axios, Turbo, Stimulus and Action Cable. Trace nested resources and mount prefixes; expand route helpers only when their definitions and arguments are evidenced. The current script excludes ERB templates, limiting evidence for generated links and forms.

## 3. Active Record and SQL Injection
- Inspect where, find_by_sql, connection.execute, exec_query, order, joins and Arel.sql. Can interpolation or concatenation place untrusted data into SQL structure?
- Distinguish bound values/hash conditions from dynamic identifiers and SQL fragments. Arel.sql marks SQL as trusted; determine whether that trust is justified.
- Trace input, transformations and the reachable database operation. Raw SQL use alone does not establish injection; show the missing or ineffective protection.

## 4. Commands, Dynamic Execution and Deserialization
- Inspect eval, class_eval, instance_eval, send/public_send, system, exec, spawn, backticks and Open3. Determine whether attackers influence executable code, method selection, commands or dangerous arguments.
- Distinguish shell interpretation from argument-vector invocation; inspect executable and option control in both cases.
- Inspect Marshal.load, YAML.load, YAML.unsafe_load, YAML.safe_load options and serialized model/job data. Determine actual library/version behavior and attacker control.
- Can input influence ERB.new or other executable template source? Separate SSTI from unescaped HTML data.

## 5. Authentication, Passwords and Sessions
- Inspect session, reset_session, cookies.signed/encrypted, has_secure_password and authentication code. If Devise exists, trace configured modules, callbacks and overridden controllers.
- Assess password storage, login/reset flow, reset-token expiry/reuse, session rotation/invalidation, account enumeration and rate-limit evidence.
- For JWT/OAuth, assess verification versus decoding, trusted keys, algorithms, expiration policy, issuer/audience and callback validation. Inspect cookie flags and secret_key_base management in active deployment settings.

## 6. Authorization, Tenancy and Strong Parameters
- Trace current_user, before_action, policy_scope, authorize and authorize! where present, including inherited filters and skips. Does every sensitive action enforce role, ownership and tenant restrictions?
- Inspect scoped associations versus global find, list queries and custom actions. A lookup by ID alone does not prove IDOR; identify the unauthorized reachable operation.
- Inspect params.require/permit, params.expect where version-supported, permit!, to_unsafe_h, update and create. Can privileged owner/tenant/role attributes be assigned? Permitted parameters are not a substitute for authorization.

## 7. XSS, CSRF, CORS and Headers
- Inspect html_safe, raw, sanitize, ERB output and browser sinks. Evaluate attacker control and HTML/attribute/URL/JavaScript context, including exceptions to escaping.
- Inspect protect_from_forgery, skip_forgery_protection, authenticity tokens, session authentication and API behavior. Assess state-changing GET routes and actual browser credential attachment.
- Inspect content_security_policy, default_headers, rack-cors and proxy headers. Evaluate effective policy rather than requiring a named gem; distinguish origin reflection with credentials from rejected wildcard credentialed reads.

## 8. Files, Active Storage, SSRF and Redirects
- Trace params into send_file, File.read/write, Pathname, uploads and archive extraction. Assess containment, symlinks, ownership, content types, size and public serving behavior.
- Where Active Storage exists, inspect attachment access, signed links, expiration, proxy/controller authorization and processing jobs according to the intended data sensitivity.
- Inspect Net::HTTP, URI.open/open-uri, Faraday and HTTP clients for attacker-controlled destinations and redirects. Inspect redirect_to, return_to and allow_other_host against the actual Rails version and host policy.

## 9. Business Logic, Transactions and Background Jobs
- Check server-derived amounts, discounts, balances and workflow transitions. Inspect transactions, with_lock/lock, uniqueness constraints and idempotency for concurrent-request weaknesses.
- Inspect Active Job, Sidekiq, retries and queue payload trust. Are ownership/authorization assumptions rechecked when work executes? Are webhook signatures and replay controls evidenced?
- Inspect Action Cable connection/channel authorization, expensive queries, regexes, pagination and upload limits. Separate known application controls from unknown gateway/worker controls.

## 10. Deployment, Secrets, Logging and Dependencies
- Inspect Rails credentials, environment variables, master-key handling, force_ssl, trusted proxies, host authorization and environment-specific settings. Verify the active environment before asserting exposure.
- Inspect filter_parameters, logs, exception/debug responses and administrative audit events. Do not reproduce secrets. Assess cryptography by its actual purpose and parameters.
- Use supplied resolved dependency and advisory evidence for CVE claims. Gemfile constraints alone do not prove vulnerable installed versions. juice2.py omits Gemfile/Gemfile.lock and ERB files under its current source allowlist; explicitly flag those coverage gaps rather than assuming they were inspected.

## 10A. Hardcoded Passwords and Secrets
- Inspect supplied code, configuration, deployment files and client assets for literal passwords, API/access tokens, database credentials/URLs, JWT/session signing secrets, encryption keys, private keys and insecure default/fallback credentials. Include fixtures and test data, but distinguish placeholders and intentional examples from plausible active credentials.
- For each candidate, report only redacted type, source path/lines, apparent purpose, runtime usage and confidence. Never reproduce complete secret values or attempt to validate credentials against external services.
- Determine whether the value reaches authentication, signing, encryption or another sensitive operation and whether it is client-exposed. Recommend removal, secure provisioning and rotation/revocation when appropriate. Do not claim repository-wide absence from selected excerpts; identify omitted files and unresolved usage. Review the selected snapshot only, not Git history.
## 11. Risk, Remediation and Verification
- Prioritize risks evidenced in this topic's supplied excerpts by impact, reachability and attacker prerequisites. Do not assume findings from prior independently analyzed sections are available.
- Give Rails-appropriate fixes and regression cases using request/model/job tests as relevant. Include anonymous, other-owner, cross-tenant, invalid-input and authorized-success scenarios.
- Name missing filters, policies, callers, templates, production configuration and resolved dependencies. Distinguish SAST/SCA/integration-test coverage; source citation checks do not prove findings correct.


