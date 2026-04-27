# Java Web Audit Playbook

Use this playbook when Zhulong identifies a Java Web repository, especially
Spring Boot, Spring MVC, WebFlux, Servlet, JAX-RS, Struts2, or Java services with
Docker/Kubernetes deployment artifacts.

This is a source-to-sink audit guide, not a replacement for Docker verification
or the confirmed-bundle reporting rules.

## Fast Model

Build an `attack-surface.md` note before deep verification.

Record:

- route or endpoint
- HTTP method
- handler or controller
- authentication requirement
- user-controlled parameters from query, path, header, cookie, body, multipart, or webhook payload
- downstream sink or service reached
- current verification status

Minimum entry inventory fields:

| Route / Endpoint | Method | Handler / Controller | Authentication Requirement | Input Source | Downstream Sink / Service | Current Verification Status |
| --- | --- | --- | --- | --- | --- | --- |

## Entry Points

Prioritize:

- `@SpringBootApplication` and `main(...)` for profiles, startup configuration, and config sources
- `@RestController`, `@Controller`, `@RequestMapping`, `@GetMapping`, `@PostMapping`
- JAX-RS `@Path`, `@GET`, `@POST`
- Servlet `doGet`, `doPost`, `doPut`, `doDelete`
- `Filter`, `OncePerRequestFilter`, `HandlerInterceptor`, `ControllerAdvice`
- Spring Security `SecurityFilterChain`, custom filters, `@PreAuthorize`, `@PostAuthorize`
- Actuator, Swagger/OpenAPI, H2 console, debug routes, management ports

## Trust Boundaries

Treat these as untrusted unless proven otherwise:

- HTTP query, path variables, headers, cookies, request body, multipart files
- JSON/XML deserialization into DTOs or entities
- webhook payloads
- DB, Redis, MQ, K8s API, third-party HTTP responses
- environment variables, JVM arguments, config files, ConfigMap, Secret, and remote config

## High-Priority Sinks

Track source-to-sink flows into:

- command execution: `Runtime.getRuntime().exec`, `ProcessBuilder`
- file access: `File`, `Paths.get`, `Files.read*`, `Files.write*`, upload/extract paths
- SQL and query construction: `Statement.execute*`, string-built JDBC, JPA/Hibernate `createQuery` / `createNativeQuery`, MyBatis `${...}`
- expression and template execution: SpEL `SpelExpressionParser`, dynamic `@Value`, Thymeleaf `th:utext`, Freemarker, Velocity, OGNL
- SSRF: `RestTemplate`, `WebClient`, `HttpURLConnection`, Apache HttpClient, OkHttp, JDK `HttpClient`
- deserialization: `ObjectInputStream.readObject`, Jackson default typing / polymorphic typing, XStream, SnakeYAML
- XML parsing: `DocumentBuilderFactory`, `SAXParserFactory`, `TransformerFactory`
- auth boundaries: resource-owner checks, role checks, `permitAll`, method-level authorization
- sensitive exposure: logs, stack traces, Actuator `env`, `heapdump`, `threaddump`, config endpoints
- TLS and crypto: trust-all `TrustManager`, hostname verifier bypass, weak password hashing, hardcoded keys

## Web Vulnerability Priorities

Audit in this order for Java Web services:

1. authentication and authorization bypass, including horizontal and vertical access control
2. SQL/JPQL/MyBatis injection, especially string concatenation and `${...}`
3. command execution and unsafe shell use
4. SSRF with redirect, DNS rebinding, localhost, RFC1918, and metadata bypass
5. path traversal, unsafe upload storage, and zip slip
6. deserialization, unsafe polymorphic JSON/YAML/XML parsing, and XXE
7. template/expression injection
8. CSRF/CORS mistakes for cookie-authenticated flows
9. sensitive data exposure through logs, errors, management endpoints, or docs
10. resource exhaustion: body size, XML/JSON depth, regex, timeouts, thread pools

## Java Tooling Notes

Use tools as evidence collection, not as final proof:

- Maven: `mvn -q -DskipTests dependency:tree`
- Gradle: `gradle dependencies` or `./gradlew dependencies`
- OWASP Dependency-Check when available
- Semgrep Java rules
- SpotBugs + FindSecBugs when available

If tools are unavailable or noisy, record a skipped or non-fatal status and keep
manual source-to-sink review moving. Confirm only with Docker evidence.

## Confirmed Finding Requirements

For each Java finding, the report should include:

- source file, class, method, and relevant annotation or route
- controllable input and trust boundary
- exact sink and source-to-sink path
- why framework defaults, filters, validation, or prior fixes do not block the issue
- Docker reproduction command and direct success oracle
- practical exploitation path and conservative severity rationale
