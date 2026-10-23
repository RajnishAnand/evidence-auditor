# Popular backend technologies and conservative checks

The auditor reports a technology only when a public response exposes a
recognizable signal. A missing signal is not evidence that a backend is absent.
Ruby/Rails and Node.js detection is currently **partial**: reverse proxies,
custom cookies, and sanitized headers can make these results unreliable. Exact
backend versions are also generally unavailable unless the deployment exposes
an explicit version banner or a corroborated asset signature.
Versions are reported only when the same signal contains a version.

| Area | Examples | Safe observable checks |
| --- | --- | --- |
| Web servers | Apache, nginx, IIS, LiteSpeed, Caddy, OpenResty | `Server` header; known cache headers |
| Application servers | Gunicorn, Uvicorn, Waitress, Kestrel, Tomcat, Jetty | `Server`/`Via` headers; framework cookies |
| PHP | PHP-FPM behind Apache/nginx, mod_php | `X-Powered-By: PHP`; `PHPSESSID`; public `.php` references |
| Python | Django, Flask, FastAPI, Gunicorn/Uvicorn | server header; Django `csrftoken`; explicit assets/headers |
| Java | Servlet containers, Spring Boot, Tomcat, Jetty | `JSESSIONID`; server header; explicit framework headers |
| .NET | ASP.NET Core, IIS, Kestrel | `X-Powered-By`, `X-AspNet-Version`, session cookie, server header |
| Ruby | Rails, Puma, Passenger | Rails session cookie; server header where present *(partial)* |
| Node.js | Express, Next.js, Nuxt | `X-Powered-By: Express`; framework asset paths *(partial)* |
| CMS/platforms | WordPress, Drupal, Joomla, Shopify, Ghost | generator metadata, stable asset paths, platform headers |

## Detection certainty matrix

| Technology | Strongest public signal | Typical certainty | Version availability |
| --- | --- | --- | --- |
| nginx / Apache / IIS | Version-bearing `Server` header | High | Exact only when banner exposes it |
| PHP | `X-Powered-By: PHP/x`, `PHPSESSID` | High for PHP hint; medium for cookie-only | Often available from header, otherwise unknown |
| ASP.NET | `X-AspNet-Version`, IIS/Kestrel plus ASP.NET markers | High when version header exists | Sometimes exact |
| Java Servlet | `JSESSIONID` plus Tomcat/Jetty header | Medium to high when corroborated | Usually unknown |
| Django | `django_session`/`csrftoken` plus HTML or server evidence | Medium | Rarely exposed |
| Rails | `authenticity_token`, `_rails_session`, Rails asset conventions | Medium when two markers co-occur | Usually unknown |
| Node.js / Express | `X-Powered-By: Express`, `connect.sid`, explicit server banner | Medium; proxy-hidden origin is common | Usually unknown |
| Frontend libraries | Versioned asset path or bundle banner | Medium to high depending on corroboration | Often available from asset |

These are evidence ceilings for passive public inspection, not guarantees. A
well-configured site may intentionally expose none of these signals.

## Detection rules

- Prefer direct headers and cookie names over generic page content.
- Treat cookies as hints, not proof; proxies and custom applications can reuse
  familiar names.
- Treat `.php` references as weak runtime evidence because routes can be
  rewritten or served by another runtime.
- Do not infer a product from generic `Server: cloud`, `X-Powered-By`, or
  `X-Cache` values.
- Keep every rule's source, confidence, and limitation in the observation.

## Research references

- [OWASP Web Security Testing Guide: fingerprint web application frameworks](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/08-Fingerprint_Web_Application_Framework)
- [OWASP Web Security Testing Guide: fingerprint web servers](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server)
- [Wappalyzer/Webappanalyzer open fingerprint model](https://github.com/enthec/webappanalyzer)
- [Rails marker discussion: authenticity token and asset conventions](https://stackoverflow.com/questions/14264780/detect-if-rails-is-running-a-site)
- [Node.js detection limitations](https://stackoverflow.com/questions/25977951/how-to-know-if-a-server-is-running-node-js)

These sources support combining independent markers. They also reinforce that
reverse proxies can hide the origin and that no passive method can reliably
identify a backend that exposes no distinguishing signal.
