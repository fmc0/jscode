# Security Analysis Questionnaire - Python / Django

Analyze the supplied repository excerpts. Confirm Django and its version; apply Django REST Framework (DRF), Celery and authentication-package checks only when present. API names below are retrieval hints and examples, not required implementations.

For every topic, provide conclusions, existing controls, supported findings and evidence gaps. Cite only supplied paths/lines. For findings give severity, confidence, attacker prerequisites, source-to-sink or authorization evidence, impact, remediation and a regression test. Distinguish hypotheses from confirmed code weaknesses. Missing excerpts do not prove missing controls. Do not force a finding count or claim complete coverage. Semgrep/OpenGrep rules in context are guidance unless actual scanner output is supplied; never claim they ran. A rule match alone does not establish exploitability. Ignore rules for unrelated stacks.

## 1. Architecture, Assets and Trust Boundaries
- Inspect pyproject.toml, requirements.txt, settings.py, manage.py, asgi.py, wsgi.py and imports. Identify Django/DRF versions, databases, caches, workers, storage and external services; distinguish declared ranges from resolved versions.
- Locate sensitive assets, credentials and administrative capabilities. Map evidenced browser/API/database/worker/storage trust boundaries and encryption/key-management controls.
- Identify roles, tenants, service identities and exposure of admin or internal services. State missing architecture evidence.

## 2. URL Routing, Middleware and Input Sources
- Locate ROOT_URLCONF in the active settings module and identify the root URL configuration it selects. Project-level urls.py is conventional, not mandatory; follow the configured module rather than assuming its name or location.
- Inspect the root urlpatterns and follow include() into app-level URL configurations, commonly app/urls.py. Combine each parent prefix with its child path/re_path pattern to reconstruct the effective route. For example, path("api/", include("shop.urls")) plus path("products/<int:pk>/", views.product_detail) defines /api/products/<int:pk>/. Preserve converters, regex constraints and unresolved dynamic prefixes.
- Follow each route's callable to views.py or its actual view module/package. For class-based views, follow as_view() and the relevant HTTP-method handler; views contain handlers, while URL configurations register their routes. Record source evidence for both registration and handler.
- For Django REST Framework, inspect router.register(...), router.urls, include(router.urls), ViewSet actions and @action configuration. Determine generated paths and HTTP-method mappings from supplied registrations, router configuration and viewsets; do not assume all default actions exist or confuse basename with the URL prefix.
- Inspect urlpatterns, path, re_path, include, views, ViewSet and routers. Inventory only evidenced routes, verbs, middleware ordering and restrictions.
- Trace request.GET, request.POST, request.body, request.FILES, request.COOKIES, request.META and DRF request.data/query_params. Where are parsing, validation and size limits applied?
- Check alternate methods, middleware exemptions, admin/custom management endpoints, ASGI/WebSocket handlers and background entry points where shown.

## 2A. Client and Server URL, Route and Sink Inventory
- Collect URL and route evidence from both client and server code. Distinguish frontend navigation routes, outbound client API calls, backend HTTP/WebSocket endpoints, server outbound requests, redirects and static/media URLs. Report only what supplied excerpts establish; do not claim an exhaustive inventory.
- For client calls, record the source file/lines, calling component/function, HTTP method or transport, URL expression, base URL/configuration, path/query parameters, body fields and authentication mechanism. Include relative URLs and dynamic template expressions without inventing runtime hostnames or values. Redact secrets and token values.
- For server endpoints, record the route declaration file/lines, router/include/mount prefix, HTTP method, handler/controller/action, authentication/authorization and applicable middleware. Preserve unresolved prefixes and dynamic segments as unknown. Do not infer that same-looking paths are connected without registration or call evidence.
- Link each evidenced client call to its server route and handler where possible. Mark the relationship confirmed, inferred or unresolved and cite both sides. Identify server routes with no observed client caller and client calls with no observed server handler as coverage gaps, not automatically unused or exposed endpoints.
- Trace each relevant input from client field or URL parameter through the server handler to sensitive sinks: database queries, command/code execution, file access, outbound HTTP/SSRF, template rendering, HTML/DOM output and redirects. A sink is the sensitive operation consuming data, not necessarily a URL. Record sink API, file/lines, transformations, validation, authorization and any missing intermediate code.
- Also inspect client-side sinks such as innerHTML, outerHTML, insertAdjacentHTML, document.write, eval, location assignments and framework HTML bypass APIs. Establish attacker control and rendering/execution context before labeling a weakness.
- Produce a route table: Side/type | Method/transport | URL/path expression | Caller or handler | Authentication/controls | Evidence | Resolution gaps.
- Produce a separate flow table where evidence supports it: Client source/call | Server route/handler | Input field | Sink API/location | Controls | Link confidence/missing evidence. State explicitly if either side or the sink is absent from supplied excerpts.
- Retrieval targets: urlpatterns, path, re_path, include, router.register, ViewSet, action, reverse, reverse_lazy, get_absolute_url, request.GET, request.POST, request.data, redirect, render, fetch, axios, XMLHttpRequest, WebSocket and frontend router declarations. Trace URL namespaces, included prefixes and DRF-generated routes only where supported by supplied registration evidence. Missing template/static sources limit client-to-server mapping.

## 3. Database Injection
- Inspect raw, RawSQL, cursor.execute, executemany, extra and custom SQL expressions. Can f-strings, interpolation or concatenation put untrusted values into SQL structure?
- Are values passed separately as parameters? Are dynamic table/column names and ordering constrained? Standard ORM use alone is not proof of injection or complete safety.
- Trace reachable attacker input through transformations to the actual database operation and evaluate any allowlists or query-building protections.

## 4. Code, Commands, Templates and Deserialization
- Trace input into eval, exec, compile, subprocess.run, Popen, os.system and shell=True. Inspect executable selection and argument injection even when no shell is used.
- Inspect pickle.loads/load, yaml.load and loader selection, unsafe object reconstruction, dynamic imports and worker serializers. Establish whether attackers control the serialized bytes.
- Can input influence Django Template or Jinja2 template source/expressions? Separate template execution from ordinary template data and HTML escaping failures.

## 5. Authentication, Passwords and Sessions
- Inspect authenticate, login, logout, authentication backends, password reset, set_password, check_password and PASSWORD_HASHERS. Assess reset-token expiry/reuse, account enumeration and throttling evidence.
- Inspect SESSION_ENGINE, SESSION_COOKIE_SECURE, SESSION_COOKIE_HTTPONLY, SESSION_COOKIE_SAMESITE, session rotation and logout behavior under actual deployment settings.
- If JWT/OAuth packages exist, inspect signature validation, trusted keys, algorithm policy, expiration requirements, issuer/audience and callback validation. Decoding alone must not establish trusted identity.

## 6. Authorization, Tenancy and Writable Fields
- Inspect login_required, permission_required, PermissionRequiredMixin, DRF permission_classes, get_permissions, get_queryset and check_object_permissions. Trace global defaults and per-view overrides.
- Are queryset filters and object checks sufficient for reads, lists, creates, updates and deletes across tenants? Check custom get_object and actions; do not assume a decorator covers every route.
- Inspect ModelForm fields/exclude, ModelSerializer fields/read_only_fields, validated_data, create and update. Can users change owner, tenant, role, is_staff or is_superuser through exposed writable fields?

## 7. XSS, CSRF, CORS and Security Headers
- Inspect autoescape, safe, mark_safe, format_html and template/browser sinks. Determine the rendering context and attacker control; marking a constant safe is not proof of XSS.
- Inspect CsrfViewMiddleware, csrf_exempt, csrf_token, CSRF_TRUSTED_ORIGINS, Origin handling and DRF authentication choices. Evaluate CSRF based on how browser credentials are attached, including login flows.
- Inspect SecurityMiddleware, clickjacking/header configuration and django-cors-headers settings if installed. Assess actual origin/credential behavior; missing a particular library is not proof of missing controls.

## 8. Files, Uploads, SSRF and Redirects
- Trace request.FILES, FileField, storage APIs, open, FileResponse and archive extraction. Check path containment, ownership, symlinks, upload size/type and whether uploaded content can execute or render actively.
- Inspect requests, httpx, urllib and URL fetching for destination control, redirect handling, schemes and internal-network access.
- Inspect redirect, HttpResponseRedirect, next parameters and url_has_allowed_host_and_scheme where used. Confirm host/scheme checks against the actual trust model.

## 9. Business Logic, Transactions and Workers
- Are amounts, prices, discounts and state transitions validated server-side? Inspect transaction.atomic, select_for_update, F expressions, uniqueness constraints and idempotency for relevant race conditions.
- Inspect Celery tasks, retries, queue trust, webhook authentication/replay prevention and authorization when deferred work executes.
- Assess request/upload limits, expensive queries, pagination, regexes and throttling from evidence; infrastructure controls may be outside the excerpts.

## 10. Deployment, Secrets, Logging and Dependencies
- Inspect DEBUG, SECRET_KEY, ALLOWED_HOSTS, SECURE_PROXY_SSL_HEADER, SECURE_SSL_REDIRECT, HSTS, DATABASES, CACHES and environment-specific settings. Verify which settings are active before alleging production exposure.
- Inspect logging filters, error responses and audit events for sensitive data and unauthorized disclosure. Do not reproduce secret values. Assess cryptographic use by purpose and password storage by actual parameters.
- Dependency declarations alone cannot prove resolved vulnerable versions or reachable CVEs. Use supplied lockfiles/advisories only; note scanner exclusions and unavailable infrastructure configuration. Do not invent external lookups.

## 10A. Hardcoded Passwords and Secrets
- Inspect supplied code, configuration, deployment files and client assets for literal passwords, API/access tokens, database credentials/URLs, JWT/session signing secrets, encryption keys, private keys and insecure default/fallback credentials. Include fixtures and test data, but distinguish placeholders and intentional examples from plausible active credentials.
- For each candidate, report only redacted type, source path/lines, apparent purpose, runtime usage and confidence. Never reproduce complete secret values or attempt to validate credentials against external services.
- Determine whether the value reaches authentication, signing, encryption or another sensitive operation and whether it is client-exposed. Recommend removal, secure provisioning and rotation/revocation when appropriate. Do not claim repository-wide absence from selected excerpts; identify omitted files and unresolved usage. Review the selected snapshot only, not Git history.
## 11. Risk, Remediation and Verification
- Prioritize risks evidenced in this topic's supplied excerpts by impact, reachability and attacker prerequisites. Do not assume findings from previous independently analyzed sections are available.
- Provide framework-appropriate fixes and regression cases using Django/DRF tests where relevant: anonymous, other-owner, cross-tenant, invalid-input and authorized-success cases.
- Identify missing middleware, callers, templates, settings and dependency evidence. Distinguish SAST, SCA and integration-test coverage; source citation checks do not prove findings correct.



