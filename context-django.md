# Python / Django security review reference

## Scope and evidence
Apply these checks only to evidenced Python/Django APIs and installed extensions. Confirm versions, imports, aliases and active settings. This is LLM reference material, not scanner output. Rules below are original Semgrep-style triage examples, not executed or engine-tested rules. A metavariable represents syntax, not proof of attacker control. Confirm input source, transformations, reachable operation, attacker permissions and effective controls before reporting a vulnerability. Cite only supplied code; missing excerpts mean unknown controls. Redact secret values. Distinguish severity from confidence and identify missing cross-file evidence.

## Routing and architecture
ROOT_URLCONF selects the root URL configuration; urls.py is conventional, not mandatory. Follow urlpatterns and include() into app-level configurations and combine parent/child prefixes. Trace function views, class-based as_view(), DRF router.register/router.urls and custom actions. Router basename is not the URL prefix. Do not invent generated actions absent supporting registration and viewset evidence. Client calls, server routes and sensitive sinks are different objects; connect them only with evidence.

## Rule examples
These broad rules locate operations for inspection, including safe uses. They do not implement complete taint or authorization analysis. Extract the YAML and validate it with your engine and positive/negative fixtures before scanner use. The Markdown document is not an executable rule configuration.

```yaml
rules:
  - id: review-python-dynamic-execution
    languages: [python]
    severity: WARNING
    message: Trace attacker control into dynamic code execution.
    pattern-either:
      - pattern: eval(...)
      - pattern: exec(...)
  - id: review-python-shell
    languages: [python]
    severity: WARNING
    message: Inspect command origin and shell interpretation.
    pattern-either:
      - pattern: os.system(...)
      - pattern: subprocess.run(..., shell=True, ...)
      - pattern: subprocess.Popen(..., shell=True, ...)
  - id: review-django-raw-sql
    languages: [python]
    severity: WARNING
    message: Confirm database binding and inspect query construction and parameters.
    pattern-either:
      - pattern: $CURSOR.execute(...)
      - pattern: $MANAGER.raw(...)
      - pattern: RawSQL(...)
  - id: review-python-deserialization
    languages: [python]
    severity: WARNING
    message: Inspect serialized input trust and loader configuration.
    pattern-either:
      - pattern: pickle.loads(...)
      - pattern: pickle.load(...)
      - pattern: yaml.load(...)
  - id: review-django-safe-html
    languages: [python]
    severity: WARNING
    message: Inspect input provenance and actual HTML rendering context.
    pattern: mark_safe(...)
  - id: review-python-hardcoded-password-candidate
    languages: [python]
    severity: WARNING
    message: Inspect literal credential candidate; redact values and distinguish fixtures.
    pattern-either:
      - pattern: password = "..."
      - pattern: SECRET_KEY = "..."
      - pattern: API_KEY = "..."
```

## Security checks and false-positive controls
SQL: Inspect raw, RawSQL, cursor.execute, extra, interpolation/f-strings and dynamic identifiers. Bound values and ordinary ORM queries may be safe; inspect actual construction rather than flagging every raw call. Determine whether request.GET/POST/body/data or persisted attacker input controls query structure.
Commands/code: Inspect eval/exec, subprocess, os.system and executable/argument selection. No-shell execution avoids shell parsing but does not eliminate dangerous program arguments. Check aliases and wrappers missed by example patterns.
Templates/XSS: Attacker-controlled template source or expressions can cause SSTI. Unescaped template data is an XSS concern, not automatically SSTI. Inspect autoescape, safe, mark_safe, format_html, browser sinks and output context. Constant trusted HTML is not evidence of an exploit.
Deserialization: Establish control of bytes reaching pickle or unsafe YAML/object reconstruction. Confirm loader behavior and version; yaml.load is not universally unsafe with every loader. Check Celery serialization and queue trust where relevant.
Authentication: Inspect authenticate/login/logout, backends, password reset and session rotation/invalidation. Check password hashing configuration and actual work factors. For JWT packages distinguish decode from verification, require appropriate algorithm/key trust and assess expiration, issuer and audience policy.
Authorization: Trace login_required, permission_required, DRF defaults/overrides, get_queryset, get_object and check_object_permissions. Check list/create/custom actions and ownership/tenant enforcement. A lookup by ID alone is not proof of IDOR. ModelForm/ModelSerializer writable fields must not expose privileged owner, tenant, role or staff attributes without authorization.
CSRF/headers: Inspect middleware order, csrf_exempt, CSRF_TRUSTED_ORIGINS and authentication mechanisms. Evaluate defenses according to automatic browser credential attachment. Absence of a named package does not prove missing protection. Inspect effective CORS/header policy and distinguish arbitrary origin reflection from wildcard credentialed reads browsers reject.
Files/network: Inspect storage/open/FileResponse, upload limits, path containment, symlinks and ownership. Trace requests/httpx/urllib destinations, redirects and schemes for SSRF. Validate redirect hosts/schemes against intended destinations.
Cryptography/secrets: Search code, settings, configuration, templates and deployment files for hardcoded passwords, API tokens, signing/encryption keys, private keys, database URLs and fallback credentials. Distinguish placeholders/test values; never print full secrets. Examine crypto purpose, key derivation, authenticated encryption, nonce/IV handling, randomness and TLS certificate verification. MD5/SHA-1 used as a nonsecurity checksum is different from password storage. Environment variables alone do not prove key strength or rotation.
Logic/availability: Check server-derived prices/amounts, transaction.atomic, locks/constraints, idempotency, job authorization and authenticated replay-resistant webhooks. Determine request/query/upload limits and resource-exhaustion paths from evidence.
Deployment/logging: Confirm active DEBUG, ALLOWED_HOSTS, SECRET_KEY, proxy/TLS settings and environment overrides. Inspect logs, error responses and audit events without reproducing credentials. Infrastructure controls outside the excerpts remain unknown.

## Review limits
juice2.py selects limited excerpts by question keywords and caps context; this document does not broaden source coverage or run scanners. Follow-ups should request missing callers, settings, templates and permissions. Dependency manifests alone cannot establish resolved vulnerable versions or reachable CVEs; use actual supplied lockfiles/advisories and flag exclusions. No claim of repository-wide secret absence is justified by selected excerpts.

Reference: https://docs.djangoproject.com/en/dev/topics/security/
