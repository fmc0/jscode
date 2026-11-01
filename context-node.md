# Node.js / Express / Sequelize security review reference

## Scope and evidence standard
This is reference material for LLM review, not scanner output. The YAML below contains original Semgrep-style review rules; juice2.py does not execute them. Never claim a scanner ran or a rule matched unless actual scanner results are supplied. These examples have not been validated with a scanner engine.
Confirm language, imports, aliases, versions, middleware ordering and runtime configuration. $DB and $JWT do not establish library identity.
A suspicious pattern is a review candidate, not proof of a vulnerability. Establish the input source, transformations, sensitive operation, reachable route, attacker permissions, and effective controls. Cite only supplied source lines. Describe missing evidence as unknown, not an absent control. Separate severity from confidence. Do not force a minimum number of findings.
Report rule/category, severity, confidence, source lines, data flow, controls, impact, fix and regression test. Label incomplete paths as hypotheses.

## Compact rule examples
Broad patterns can match safe code and do not trace data flow. $INPUT is syntax, not proof of untrusted data. WARNING is triage priority. Extract and validate/test the YAML before scanner use; Markdown is not scanner configuration.

```yaml
rules:
  - id: review-js-dynamic-execution
    languages: [javascript, typescript]
    severity: WARNING
    message: Inspect dynamic execution for attacker-controlled code.
    pattern-either:
      - pattern: eval($INPUT)
      - pattern: new Function(...)
      - pattern: Function(...)
  - id: review-js-process-execution
    languages: [javascript, typescript]
    severity: WARNING
    message: Confirm child_process binding and inspect command, arguments and shell options.
    pattern-either:
      - pattern: $CP.exec(...)
      - pattern: $CP.execSync(...)
      - pattern: $CP.spawn(...)
      - pattern: $CP.execFile(...)
  - id: review-sequelize-raw-operation
    languages: [javascript, typescript]
    severity: WARNING
    message: Confirm Sequelize binding and inspect SQL construction and parameterization.
    pattern-either:
      - pattern: $DB.query(...)
      - pattern: $DB.literal(...)
  - id: review-request-body-model-write
    languages: [javascript, typescript]
    severity: WARNING
    message: Inspect field allowlists and authorization before persisting request bodies.
    pattern-either:
      - pattern: $MODEL.create($REQ.body, ...)
      - pattern: $MODEL.update($REQ.body, ...)
      - pattern: $MODEL.upsert($REQ.body, ...)
  - id: review-jwt-decode
    languages: [javascript, typescript]
    severity: WARNING
    message: Confirm JWT binding; decoding alone must not establish trusted identity.
    pattern: $JWT.decode(...)
  - id: review-html-response
    languages: [javascript, typescript]
    severity: WARNING
    message: Inspect response type, attacker input and contextual output handling.
    pattern-either:
      - pattern: $RES.send(...)
      - pattern: $ELEMENT.innerHTML = $VALUE
  - id: review-file-response
    languages: [javascript, typescript]
    severity: WARNING
    message: Inspect path containment and authorization for file responses.
    pattern-either:
      - pattern: $RES.sendFile(...)
      - pattern: $RES.download(...)
```

## Confirmation and remediation by category
Injection: Trace req.body, req.query, req.params, headers, uploaded data and stored attacker input into SQL, NoSQL, process or template operations. Sequelize query/literal is not inherently vulnerable: inspect bind/replacements and how identifiers are constructed. Prefer bound values and explicit identifier allowlists. spawn/execFile without a shell avoids shell interpretation but may still permit unsafe executable selection or argument injection. Inspect destructured imports and wrappers that the simple examples miss.
Templates/XSS: SSTI requires attacker influence over template source or executable template expressions. Unescaped data in HTML is an XSS concern, not automatically SSTI. Check response Content-Type and the actual HTML/attribute/URL/JavaScript rendering context. Use contextual encoding; sanitize intentionally allowed HTML with an appropriate maintained sanitizer. DOMPurify is not a general SQL, path or server input validator. res.send with constant content is not a vulnerability.
JWT/authentication: Trace jwt.verify versus jwt.decode, trusted key selection, algorithm allowlists, issuer/audience where applicable, expiration policy and authorization after verification. Environment variables do not prove a secret is strong. Check whether expiration is required as well as validated when present. Decoding for display after successful verification can be safe. Assess token lifetime/revocation against the application threat model.
Authorization: Trace route registration, global/router middleware, ownership/tenant predicates and model hooks. findByPk(req.params.id) alone does not prove IDOR. Confirm an unauthorized user can reach another user's resource and perform the operation. Evaluate each HTTP verb and administrative action.
Mass assignment: Determine whether attacker-writable attributes include privileged fields. Check upstream schema validation, explicit field selection, Sequelize fields options and model restrictions. Passing req.body is a candidate, not a confirmed privilege escalation.
Files/SSRF: Check path canonicalization and containment, symlinks, upload names/types/size, download ownership, and archive extraction. For outbound fetch/axios/http calls assess destination control, redirects, allowed schemes and private-network destinations in the deployment context.
Middleware: Evaluate actual header policy and middleware coverage. Missing Helmet does not prove missing headers; proxies or other code can set them. Assess CSP directives in context. CORS controls browser response access, not server authorization. Arbitrary origin reflection with credentials deserves review. A literal wildcard origin plus credentials is rejected for credentialed browser reads and is not itself proof of data theft.
CSRF/session: Determine whether browsers attach authentication automatically. Inspect CSRF tokens, Origin checks, SameSite behavior and state-changing GET routes. No particular middleware package is required. Evaluate cookie httpOnly/secure/sameSite, TLS termination, proxy trust, session rotation and invalidation in the deployed environment. SameSite=Strict is not mandatory for every application.
Validation/logic: Confirm server-side schemas, allowed object keys, types, length/range limits and handling of arrays/nested objects. Check negative quantities, server-derived prices, coupon reuse, concurrency and transaction boundaries. Rate limiting may be applied by a gateway; missing local middleware is not proof it is absent.
Crypto/logging/errors: Identify the security purpose before judging an algorithm. MD5/SHA-1 for password storage or security-sensitive integrity is concerning; nonsecurity checksums are different. Inspect password hashing parameters, random generation, key management, sensitive log fields, production error responses and audit integrity.

## Coverage limitations
Inspect package.json, bootstrap files, routes, middleware, models, configuration and relevant tests. Versions/ranges in package.json do not establish resolved dependency versions or exploitable CVEs; use lockfiles and current advisory/SCA evidence for that. juice2.py excludes several lockfiles and selects limited excerpts, so complete endpoint inventories, dependency audits and claims of repository-wide absence are unsupported.
Context does not affect source selection. Put API names in question.md and split broad topics. Request missing callers/middleware in follow-up reviews. Clean excerpts do not prove repository security.


