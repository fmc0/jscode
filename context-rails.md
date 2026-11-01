# Ruby / Ruby on Rails security review reference

## Scope and evidence
Apply these checks only to evidenced Ruby/Rails APIs and installed gems. Confirm versions, aliases, active environment and inherited behavior. This is LLM reference material, not scanner output. Rules below are original Semgrep-style triage examples, not executed or engine-tested rules. A metavariable represents syntax, not proof of attacker control. Confirm input source, transformations, reachable operation, attacker permissions and effective controls before reporting a vulnerability. Cite only supplied code; missing excerpts mean unknown controls. Redact secret values. Distinguish severity from confidence and identify missing cross-file evidence.

## Routing and architecture
Inspect config/routes.rb, resources, namespace, scope, mount and custom routes. Resolve nested prefixes and route helpers using declarations and arguments. Follow controller actions, inherited before_action filters, skips and authorization policies. Route existence does not prove unauthorized reachability. Inspect Action Cable connection/channel authorization where present. Client navigation, API calls, server routes and sensitive sinks must be recorded separately, with evidence for links between them.

## Rule examples
These broad rules locate operations for inspection, including safe uses. They do not implement complete taint or authorization analysis. Extract the YAML and validate it with your engine and positive/negative fixtures before scanner use. The Markdown document is not an executable rule configuration.

```yaml
rules:
  - id: review-ruby-dynamic-execution
    languages: [ruby]
    severity: WARNING
    message: Inspect attacker influence over executable code.
    pattern-either:
      - pattern: eval(...)
      - pattern: $OBJ.class_eval(...)
      - pattern: $OBJ.instance_eval(...)
  - id: review-ruby-process-execution
    languages: [ruby]
    severity: WARNING
    message: Inspect command parsing, executable selection and arguments.
    pattern-either:
      - pattern: system(...)
      - pattern: exec(...)
      - pattern: spawn(...)
  - id: review-rails-raw-sql
    languages: [ruby]
    severity: WARNING
    message: Inspect SQL construction, value binding and identifier allowlists.
    pattern-either:
      - pattern: $MODEL.find_by_sql(...)
      - pattern: $CONNECTION.execute(...)
      - pattern: Arel.sql(...)
  - id: review-ruby-deserialization
    languages: [ruby]
    severity: WARNING
    message: Inspect input provenance and loader/version behavior.
    pattern-either:
      - pattern: Marshal.load(...)
      - pattern: YAML.load(...)
      - pattern: YAML.unsafe_load(...)
  - id: review-rails-html-bypass
    languages: [ruby]
    severity: WARNING
    message: Trace untrusted content and actual output context.
    pattern-either:
      - pattern: $VALUE.html_safe
      - pattern: raw(...)
  - id: review-rails-parameter-bypass
    languages: [ruby]
    severity: WARNING
    message: Inspect writable privileged fields and authorization.
    pattern-either:
      - pattern: $PARAMS.permit!
      - pattern: $PARAMS.to_unsafe_h
```

## Security checks and false-positive controls
SQL: Inspect where/order/joins, find_by_sql, connection.execute and Arel.sql. Distinguish bound values/hash conditions from interpolation and attacker-controlled SQL fragments. Arel.sql marks trust; determine whether input warrants it. A raw operation alone does not establish injection.
Execution: Inspect eval/class_eval/instance_eval, send/public_send, system/exec/spawn, backticks and Open3. Distinguish block execution from string evaluation, shell interpretation from argument-vector execution, and authorized method dispatch from attacker-controlled sensitive methods. No-shell execution can still accept dangerous executable names or options.
Deserialization/templates: Inspect Marshal/YAML behavior by runtime/library version, safe loader options and actual input provenance. YAML.load behavior varies by version. Attacker influence over ERB/template source is distinct from unescaped HTML data causing XSS.
Authentication: Inspect authentication controllers, has_secure_password, Devise if installed, reset flows, session rotation/reset_session and logout. Evaluate hashing parameters, token expiry/reuse and account enumeration. For JWT/OAuth inspect verification, trusted keys, algorithm policy, issuer/audience and redirect/callback validation.
Authorization: Trace current_user, policy_scope/authorize or authorize! only where applicable. Inspect inherited filters, skip_before_action and object/tenant scoping across reads/lists/writes/deletes. An ID lookup alone is not proof of IDOR. Strong parameters restrict assignment, not authorization: inspect require/permit, version-supported expect, permit!, to_unsafe_h and model-level assignment restrictions.
Browser controls: Inspect raw/html_safe/sanitize and browser sinks in their actual context. Trusted constants may be safe. Inspect protect_from_forgery/exemptions, actual session/cookie authentication, Origin policy and state-changing GET routes. Inspect CSP/default headers, rack-cors if present and infrastructure controls without requiring any particular gem.
Files/network: Inspect send_file, File APIs, path containment, symlinks, ownership, upload limits, public content serving and Active Storage access. Signed links should be assessed against data sensitivity and access policy, not presumed private indefinitely. Trace Net::HTTP, open-uri/URI.open and Faraday destinations/redirects for SSRF. Evaluate redirect_to, return_to and allow_other_host in the actual Rails version.
Cryptography/secrets: Search Ruby, credentials/configuration, deployment files, templates and client assets for hardcoded passwords, API/access tokens, database credentials, secret_key_base, signing/encryption keys, private keys and fallback secrets. Distinguish placeholders/test values; redact values. Inspect key lifecycle/derivation, encryption authenticity, nonce/IV reuse, randomness, password hashing and certificate verification. Encrypted credentials are not plaintext leakage by themselves; inspect master-key exposure separately. Environment variables do not prove strong keys.
Logic/availability: Inspect server-derived amounts, workflow transitions, transactions/locks/constraints, idempotency, job retries and authorization at execution time. Check webhook authentication/replay protection and per-message authorization for real-time connections. Assess expensive queries, regexes, pagination and upload limits from evidence.
Deployment/logging: Confirm production environment, force_ssl, trusted proxies, host authorization, debug/error behavior and filter_parameters. Inspect audit events and sensitive logging. Infrastructure controls outside the excerpts remain unknown.

## Review limits
juice2.py selects limited excerpts by question keywords and caps context; this document does not broaden source coverage or run scanners. Its existing file allowlist omits extensionless Gemfile/Gemfile.lock and ERB templates: name these gaps and request needed evidence. Dependency declarations alone do not prove resolved vulnerable versions or reachable CVEs. No claim of repository-wide secret absence is justified by selected excerpts. Request missing filters, policies, route helpers, templates and callers for follow-up.

Reference: https://guides.rubyonrails.org/security.html
