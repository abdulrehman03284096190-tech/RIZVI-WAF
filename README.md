# RIZVI WAF

RIZVI WAF is a Python/Tkinter desktop reverse-proxy prototype for inspecting
HTTP traffic. The **Connected Applications** page can manage multiple
administrator-authorized web applications. Each registered application gets a
fixed backend destination, a unique local WAF listener port, isolated WAF
settings, session statistics, and a durable event history.

The WAF does not modify or deploy code to your website. Registration alone does
not protect an application: you must start its listener and route client traffic
through that listener. The dashboard reports protection as active only after
the proxy has processed a request through its inspection rules.

## Requirements and run

- Python 3.10 or later (standard library only)
- Tkinter for the desktop UI

```powershell
python app.py
```

`python run.py` remains a compatibility launcher.

## Build the Windows installer

The Windows installer bundles the application, Python runtime, Tcl/Tk, and
build-time collected files into a per-user installation. End users do not need
to install Python or application dependencies. The installer provides a
branded setup wizard, an installation-directory page, Start Menu and optional
desktop shortcuts, version/publisher metadata, and an Inno Setup uninstaller.
It targets 64-bit Windows 10 and 11. Uninstalling preserves the user's
configuration, event history, and audit log under `%APPDATA%\RIZVI WAF`.

Build on Windows with Python 3.10+ and Inno Setup 6:

```powershell
winget install --id JRSoftware.InnoSetup --exact
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\installer\build_windows.ps1
```

The build script creates a project-local `.venv`, installs the pinned
build-only packages from `requirements.txt`, generates the RIZVI WAF icon and
wizard branding, runs PyInstaller, then compiles the setup program. It does
not change the machine-wide PowerShell execution policy. The final installer
is `dist\installer\RIZVI-WAF-Setup-1.0.0.exe`; the unpacked application is in
`dist\RIZVI WAF\`. Review the generated installer and test it on a clean
Windows 10/11 machine before distribution. The executable is unsigned, so
Windows may display SmartScreen warnings until the publisher signs it.

## Production protection on AWS (ALB)

For production traffic, use AWS WAFv2 in the AWS request path instead of
exposing the local Python proxy. This project includes
[`infrastructure/aws-waf-alb.template.json`](<D:/RIZVI WAF/infrastructure/aws-waf-alb.template.json>),
a CloudFormation template that associates a **regional** Web ACL with an
existing Application Load Balancer. It enables AWS managed IP reputation,
Common Rule Set (including common XSS detections), Known Bad Inputs, SQL
injection rules, and a per-source-IP rate rule. It also creates WAF CloudWatch
logging with Authorization, Cookie, and query-string redaction, a selectable
retention period, and optional customer-managed KMS encryption.

The template's default is `ManagedRuleActionMode=BLOCK`. Deploy to staging
first with `COUNT`, inspect WAF metrics/logs for false positives, tune the
rate limit and application exceptions, then explicitly deploy `BLOCK` after
approval. AWS WAF configuration is separate from the desktop app: the
Connected Applications registry does not deploy, monitor, or report the
managed AWS Web ACL, and its local Python `PROTECTED` status is not evidence
that AWS WAF is attached.

The template assumes an existing ALB, listeners, target group, and application.
It does not provision DNS, an ACM certificate, ALB security groups, targets,
or application code. The ALB must already serve the intended application; its
HTTPS listener should use an ACM certificate, and its security groups should
allow only intended client ingress and ALB-to-target traffic. Deploy this stack
in the **same AWS Region and account** as the ALB. If CloudFront is the public
entry point, attach a CloudFront-scope Web ACL to the distribution instead;
this ALB template is not the right attachment point for that architecture.

### Deploy to staging

Install/configure the AWS CLI with an explicitly selected profile and a
least-privilege deployment role. Obtain the ALB ARN and verify the active AWS
account and region before deploying. This command changes AWS resources; review
the CloudFormation change set and get your organization's approval first:

```powershell
aws sts get-caller-identity --profile staging
aws cloudformation deploy `
  --profile staging `
  --region us-west-2 `
  --stack-name rizvi-waf-staging `
  --template-file infrastructure\aws-waf-alb.template.json `
  --parameter-overrides `
    ApplicationLoadBalancerArn=arn:aws:elasticloadbalancing:us-west-2:123456789012:loadbalancer/app/example/0123456789abcdef `
    ManagedRuleActionMode=COUNT `
    RateLimit=2000 `
    LogRetentionDays=30 `
    MetricPrefix=RizviStagingWAF `
  --no-execute-changeset
```

Replace the example ARN, region, account, profile, and stack name with verified
staging values. `--no-execute-changeset` creates a pending change set only.
List and inspect it before execution:

```powershell
aws cloudformation list-change-sets `
  --profile staging `
  --region us-west-2 `
  --stack-name rizvi-waf-staging `
  --output table

aws cloudformation describe-change-set `
  --profile staging `
  --region us-west-2 `
  --stack-name rizvi-waf-staging `
  --change-set-name <reviewed-change-set-name>
```

Only after explicit approval, execute the reviewed change set:

```powershell
aws cloudformation execute-change-set `
  --profile staging `
  --region us-west-2 `
  --stack-name rizvi-waf-staging `
  --change-set-name <reviewed-change-set-name>
```

`COUNT` logs/metrics matches without blocking them, so it is for
observation—not production protection. After staging review, create and review
a separate production change set for the production ALB with
`ManagedRuleActionMode=BLOCK`. Choose a rate threshold based on real
application traffic, not the sample value.

Verify the CloudFormation stack outputs, then confirm the association and
logging configuration in the AWS WAF console and send both known-safe and
approved test requests through the ALB. Check the `aws-waf-logs-*` log group,
metrics, and application health. AWS WAF changes can take time to propagate.
Do not delete the stack to “turn off” a false positive; update the Web ACL
through a reviewed change set, and retain incident/audit records.

AWS WAF and CloudWatch logging incur AWS charges; check current regional
pricing and logging volume before enabling this in production. WAF body
inspection for ALB has AWS-defined size limits, and managed rules can have
false positives. Redaction protects WAF logs only; it is not a substitute for
application-level data minimization or secure logging. Keep the local Python
proxy loopback-only and do not place it between public clients and the ALB.

## Connect and protect an application

1. Start the web application as usual and note its backend URL, including its
   scheme and port. Examples: `http://127.0.0.1:8000`,
   `http://localhost:3000`, or `https://app.example.com:8443`.
2. In RIZVI WAF, open **Connected Applications** → **Add Application**.
3. Enter a unique application name, backend URL, and an unused WAF listen port
   from `1` to `65535`. A backend's domain name or IP address and its port are
   specified in the backend URL. Optionally add client-facing hostnames/IPs
   that the listener should accept; the backend hostname is accepted by
   default.
4. Confirm that you own or are authorized to proxy the backend. Optional
   certificate and private-key fields enable HTTPS on the WAF-to-client side.
5. Select the application and choose **Connect** to test backend TCP
   reachability (and certificate validation for an HTTPS backend). This test
   does not start protection.
6. Choose **Start Protection** and confirm. The listener is bound to
   `127.0.0.1:<WAF-port>`. Point a browser, local client, or trusted local
   reverse proxy at that listener. For example, if the WAF port is `8081`, use
   `http://127.0.0.1:8081`.
7. Check **Connection Status**, **Protection Status**, request counts, and
   blocked counts in the applications registry. A running listener with no
   inspected requests is shown as awaiting traffic, not protected.

Each listener is permanently mapped to one configured backend; an incoming
`Host` header must match the backend hostname, loopback, or a registered
application hostname. If the `Host` header includes a port, it must match that
listener. A `Host` header is never used to select a destination. Different
applications cannot share a WAF port. DNS addresses are resolved when the
proxy starts, prohibited destinations are rejected, and the resolved addresses
are pinned for upstream connections to reduce DNS-rebinding/SSRF risk. Loopback
and private-network destinations are supported for development and internal
applications; public domain names and IP addresses are also supported.

The **Connect**, **Start Protection**, **Stop Protection**, **Edit**, **Manage
Rules**, and **Disconnect** actions require administrator confirmation.
Disconnect stops the proxy and removes the registry entry but retains the
application's event-history file.

## Manage and monitor

Select an application to use:

- Filter the registry by name, backend, accepted hostname, and status; the status
  colors distinguish inspected protection from an idle listener.
- **Monitor** for its current session statistics and recent request events.
- **View Attacks** for its blocked events and matched rule results.
- **Manage Rules** to enable/disable built-in SQL injection, XSS, traversal,
  scanner and other rules; change rule weights and block threshold; set
  application-specific allow/block IP/CIDR lists; configure per-client rate
  limits; set exact path bypasses; or add custom literal-match rules.
- **Generate Report** to write a JSON security report with application
  metadata, its active security policy, current-session statistics, cumulative
  event/attack counts, and the most recent recorded events/attacks.
- **Edit** to change its name, backend URL, listener port, or TLS files while
  protection is stopped.

Each application has its own proxy engine instance, settings, rate limiter,
statistics, and appended JSONL request history. Allowlisted IPs and exact path
bypasses skip heuristic payload inspection, but do not bypass the proxy's
method, body-size, header-size, and rate checks. Custom rules are literal text
matches, not user-supplied regular expressions.

The existing **Traffic**, **Manage**, **Stats**, **Settings**, and **About**
pages continue to operate the original single-proxy mode.

## TLS and certificates

- For an **HTTPS backend**, set the backend URL to `https://...`. RIZVI WAF
  verifies the backend certificate against Python's system trust store and uses
  the backend hostname for TLS SNI and certificate-name validation. A private
  or self-signed backend CA must be trusted by the machine's Python/OpenSSL
  trust configuration; certificate verification is not disabled.
- For **HTTPS from clients to the WAF listener**, supply both a PEM certificate
  (including its certificate chain as needed) and its matching PEM private key
  in the application form. The certificate must be valid for the hostname
  clients use. Leaving both fields empty starts a plain-HTTP listener. A
  certificate error prevents the listener from starting.
- The listener remains bound to loopback even when HTTPS is enabled. To serve
  external clients, deploy a separately maintained, TLS-terminating reverse
  proxy/firewall on a properly secured host and configure it to forward only
  to the intended RIZVI WAF listener. Do not expose this prototype directly to
  the internet.

## Local configuration, event logs, and reports

On Windows, configuration and audit data are stored below
`%APPDATA%\RIZVI WAF\`; on other systems they are stored below
`~/.config/rizvi-waf/`. The `config.json` file contains the application registry
and policies. Per-application request history is appended to
`application-events\<application-id>.jsonl`, and administrator actions are
appended to `audit.jsonl`. Configuration and report replacement use
write-and-replace; audit and event appends are flushed to disk. When an event
history has a malformed record, the valid prefix is recovered and the original
file is preserved under a `.corrupt-<timestamp>-<id>` name; the registry shows
the recovery warning. Keep this directory access restricted to trusted local
administrators. Reports are written to the destination selected in the UI.

## Tests

Run the existing and multi-application integration tests with:

```powershell
python -m unittest discover -s tests -v
```

The tests cover existing inspection behavior, multiple backend routing,
per-application policy and event isolation, SQLi/XSS rules and custom rules,
authorization confirmations, duplicate and occupied ports, unavailable
backends, SSRF destination rejection, HTTPS backend failure without protocol
downgrade, invalid listener certificate handling, report replacement, health
endpoint privacy/access checks, ambiguous Host/Content-Length rejection, and
restored/corrupt event histories.

## Security limitations

This is a learning/development prototype, not a production WAF. Detection uses
heuristics and may miss attacks or block legitimate requests. The proxy has
bounded request/response sizes, does not support chunked request bodies,
WebSockets, or `CONNECT` tunneling. Gzip and deflate request bodies are
decompressed for inspection with a 1 MiB decoded-size limit. Declared body
charsets and UTF-16/UTF-32 byte-order marks are decoded for inspection;
unsupported or malformed encodings are rejected rather than forwarded
uninspected.
The proxy does not provide user accounts,
centralized authorization, HA, or production-grade audit tamper protection.
The listener is loopback-only, and the health endpoint returns only a minimal
status after normal host, IP, rate, size, and inspection checks. Desktop
confirmation prompts are not authentication or a substitute for OS-level
access control. Event and audit files are not encrypted, rotated, or tamper
proof. Use a maintained production WAF, hardened TLS termination, restricted
filesystem permissions, centralized identity/audit, and application-level
validation for real deployments; do not expose this prototype directly to the
internet.
