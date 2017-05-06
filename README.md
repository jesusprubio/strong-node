# Strong Node

An exhaustive checklist to assist in the source code security analysis of a Node.js web service. It's focused in the server side, in particular, is targeting **[Express](http://expressjs.com/)** and **[Hapi](http://hapijs.com/)** environments.

Next documents have been using as main references:

- The [SANS](https://www.sans.org/) SWAT (Securing Web Applications Technologies) [checklist](https://www.sans.org/security-resources/posters/securing-web-application-technologies-swat/60/download).
- The CWE (Common Weakness Enumeration) [dictionary](http://cwe.mitre.org/).

>This text aims to be a continuous work in progress community based project. So please feel free to contribute. :)


## 1 Errors

### **1.1 Returned errors don't include sensitive information about the user** or other user's info ([CWE-209](http://cwe.mitre.org/data/definitions/209.html))

### **1.2 Returned errors don't include sensitive information about the environment**: stack, paths, DB queries, etc (CWE-209)

#### **1.2.1 The environment variable "NODE_ENV" environment variable is set to "production"**

**Express**:  By default (if not in "production" mode) exposes the stack trace of the error to the client.

**Hapi**: Not exposed by default.

### **1.3 Default framework errors are never returned** (CWE-209)

### **1.4 A custom error page is defined** ([CWE-756](http://cwe.mitre.org/data/definitions/756.html))

- They could allow an attacker to detect it as part of a more sophisticated attack.
- Define a custom error handler. The way to achieve this is using a middleware.

**Express**:

- [The Default Error Handler](http://expressjs.com/en/guide/error-handling.html#the-default-error-handler)
- [http-errors](https://github.com/jshttp/http-errors):
  >Create HTTP errors for Express, Koa, Connect, etc. with ease".

**Hapi**:

- Custom implementations: http://stackoverflow.com/a/28044412/2087521, http://stackoverflow.com/a/32185406/2087521
- [Boom](https://github.com/hapijs/boom): Easy consistent HTTP errors.

### **1.5 The app takes care of ["uncaughtException"](https://nodejs.org/api/process.html#process_event_uncaughtexception) events** to avoid a the application stop (["denial of service"](https://en.wikipedia.org/wiki/Denial-of-service_attack) - [CWE-248](http://cwe.mitre.org/data/definitions/248.html))

### **1.6 The app takes care of ["unhandledRejection"](https://nodejs.org/api/process.html#process_event_unhandledrejection) events**. The same idea but with [promises](http://www.html5rocks.com/en/tutorials/es6/promises/?redirect_from_locale=es) (CWE-248)

- This kind of exceptions mean that the application is in an undefined state. So don't try to simply restart the application again without properly recovering from the exception or fixing the bug. This could head to additional unforeseen and unpredictable issues.
>- *So what's the best way of dealing with uncaught exceptions? There are many opinions floating around on this.*
>- *You application shouldn't have uncaught exceptions. This is clearly insane.*
>- *You should let your application crash, find uncaught exceptions and fix them. This is clearly insane.*
>- *You should swallow errors silently. This is what lots of people do and it is bad.*
>- *You should let your application crash, log errors and restart your process with - something like upstart, forever or monit. This is pragmatic.*
>- *You should start using domains to handle errors. Clearly the way to go, although this is an experimental feature of Node.*
- (from [Uncaught Exceptions in Node.js](http://shapeshed.com/uncaught-exceptions-in-node))
- Last two cases can be considered safe.
- Further reading: About how to handle errors by [Joyent](https://www.joyent.com/) -> http://www.joyent.com/developers/node/design/errors

**Hapi**: [Poop](https://github.com/hapijs/poop): "hapi plugin for handling uncaught exceptions".

**Heroku**: Auto-restart through the [Dyno crash restart policy](https://devcenter.heroku.com/articles/dynos#dyno-crash-restart-policy).

### **1.7 The content of the errors should avoid to reason about any internal state of the application** ([CWE-203](http://cwe.mitre.org/data/definitions/203.html))

- A common example is a response like: "Invalid login" vs. "User not found". If we use the second we are allowing a possible brute-force of our usernames.
- Some modules can help to send consistent ones (easier to reason about).

**Express**/**Hapi**: See point 1.4

### **1.8 The time to return an error should avoid to reason about any internal state of the application"** ([CWE-208](http://cwe.mitre.org/data/definitions/208.html))

- A common example is when the combination "username/password" is "good/bad" vs "bad/bad".
- To detect it:
  - Use this [ESLint](http://eslint.org/) rule : ["detect-possible-timing-attacks"](https://github.com/nodesecurity/eslint-plugin-security/blob/master/rules/detect-possible-timing-attacks.js).
  - Some tools to automate it: [nanown](https://github.com/ecbftw/nanown), [time_trial](https://github.com/dmayer/time_trial)
- To prevent it use secure libraries to compare like:
  - ["cryptiles"](https://github.com/hapijs/cryptiles) (Hapi project)
  - ["credential"](https://github.com/ericelliott/credential)
  - ["safe-compare"](https://github.com/Bruce17/safe-compare)

### **1.9 All dependencies generated errors also respect the points of this section** ([CWE-211](http://cwe.mitre.org/data/definitions/211.html))

- Control all our errors, massaging them if needed to avoid the risks commented in these last points.
- Use mature modules.
- Use secure modules. ["nsp"](https://github.com/nodesecurity/nsp) allows you to automate the search of dependencies with known vulnerabilities. Add it to your development workflow.


## 2 Input and output

### **2.1 The HTTP header "x-powered-by" is disabled** in the responses

- To avoid the framework fingerprinting.

**Express**: Enabled by default, two options:

- Use `app.disable('x-powered-by')`.
- Use [Helmet](https://github.com/helmetjs/helmet) middleware (["hide-powered-by" plugin](https://github.com/helmetjs/hide-powered-by)).

**Hapi**: Disabled by default.

### **2.2 The encoding is correctly set** for all routes ([CWE-172](http://cwe.mitre.org/data/definitions/172.html))

**Express**: The middleware ["body-parser"](https://github.com/expressjs/body-parser/) provides a comfortable mechanism to support this.

**Hapi**: Multiple options can be set [for an specific route](https://github.com/hapijs/hapi/blob/master/API.md#route-options) ("parse" option).

>If parsing is enabled and the 'Content-Type' is known (for the whole payload as well as parts), the payload is converted into an object when possible

### **2.3 Inputs with sensitive data are never auto-completed/cached** in the browser ([CWE-524](http://cwe.mitre.org/data/definitions/524.html))

- Use the [HTML input "autocomplete" Attribute](http://www.w3schools.com/tags/att_input_autocomplete.asp) in the client side to avoid be cached by the browser.

### **2.4 The HTTP header "Cache-Control" is disabled** in the responses (CWE-524)

### **2.5 The HTTP header "Etag" is disabled** in the responses (CWE-524)

**Express**: Use [Helmet](https://github.com/helmetjs/helmet) middleware (["nocache" plugin](https://github.com/helmetjs/nocache)). Remember to also disable the [Etag](https://isc.sans.edu/diary/The+Security+Impact+of+HTTP+Caching+Headers/17033) ("noEtag").

**Hapi**: All kind of cache disabled by default, just confirm the code it's not using anyone [included here](http://hapijs.com/tutorials/caching). They can also be enabled [for an specific route](https://github.com/hapijs/hapi/blob/master/API.md#route-options).

### **2.6 The header "x-xss-protection" is being set** ([CWE-79](http://cwe.mitre.org/data/definitions/79.html))

**Express**: Use [Helmet](https://github.com/helmetjs/helmet) middleware (["xssFilter" plugin](https://github.com/helmetjs/x-xss-protection)) to improve protection in new browsers.

**Hapi**: Disabled by default, the framework supports it through the [route options](https://github.com/hapijs/hapi/blob/master/API.md#route-options) "security" ("xss" field).

### **2.7 Escaping potentially untrusted inputs is applied** for all user entries (CWE-79, [CWE-77](http://cwe.mitre.org/data/definitions/77.html), [CWE-89](http://cwe.mitre.org/data/definitions/89.html))

[**Handlebars**](http://handlebarsjs.com/): The function ["escapeExpression"](https://github.com/wycats/handlebars.js/blob/88c52ded2e81b4b01d12c16e337b0bc4a453a813/lib/handlebars/utils.js#L52) is used [by default](http://handlebarsjs.com/expressions.html).

>Handlebars HTML-escapes values returned by a {{expression}}. If you don't want Handlebars to escape a value, use the "triple-stash", {{{"*).

[**Dust.js**](http://www.dustjs.com/): Enabled [by default](https://github.com/linkedin/dustjs/wiki/Dust-Tutorial#more-on-dust-output-and-dust-filters).

>All output values are escaped to avoid Cross Site Scripting (XSS) unless you use filters"*).

[**Swig**](http://paularmstrong.github.io/swig): The options ["autoescape"](http://paularmstrong.github.io/swig/docs/tags/) is needed.

Always use an validator for all the parameters used in each route:

**Express**: [express-validator](https://github.com/ctavan/express-validator)

**Hapi**: [joi](https://github.com/hapijs/joi)

### **2.8 Context-sensitive output escaping is applied** for all output values (CWE-79)

>However, contextual escaping is missing in most template frameworks including Handlebars JS, React JSX, and Dust JS.

(by [Yahoo’s Paranoid Labs](https://yahoo-security.tumblr.com/post/128130790295/paranoid-labs-open-source-and-solving-xss-in)).

Their solutions: [secure-handlebars](https://github.com/yahoo/secure-handlebars), [express-secure-handlebars](https://github.com/yahoo/express-secure-handlebars).

- *"Blindly-escaping is insufficient"* ([by Yahoo](https://yahoo.github.io/secure-handlebars/blindlyescaping.html))
- [Reducing XSS by way of Automatic Context-Aware Escaping in Template Systems](https://security.googleblog.com/2009/03/reducing-xss-by-way-of-automatic.html) (Google, 2009)
- Deep explanation and demo included in the [section A3 of NodeGoat tutorial](http://nodegoat.herokuapp.com/tutorial/a3).

### **2.9 For IE specific output escaping is applied** for all output values

**Express**: Use [Helmet](https://github.com/helmetjs/helmet) middleware (["ienoopen" plugin](https://github.com/helmetjs/ienoopen)).
**Hapi**: Disabled by default, the framework supports it through the [route options](https://github.com/hapijs/hapi/blob/master/API.md#route-options) "security" ("noOpen" field).

### **2.10 The app uses parametrized database queries** if a SQL database is being used ([CWE-89](http://cwe.mitre.org/data/definitions/89.html))

- Use escaped values:
  - [MySQL](https://github.com/felixge/node-mysql#escaping-query-values).
  - [PostreSQL](https://github.com/brianc/node-postgres)
- Deep explanation and demo included in the [section A1 (section B) of NodeGoat tutorial](http://nodegoat.herokuapp.com/tutorial/a3).

### **2.11 The "strict" options is used in the whole code**, to apply more defenses ([CWE-77](http://cwe.mitre.org/data/definitions/77.html))

ESLint rule: ["strict"](http://eslint.org/docs/rules/strict).

### **2.12 App code doesn't use "eval" at all** (CWE-77)

ESLint rules:

- ["no-eval"](http://eslint.org/docs/rules/no-eval).
- ["detect-eval-with-expression"](https://github.com/nodesecurity/eslint-plugin-security/blob/master/rules/detect-eval-with-expression.js).

### **2.13 App doesn't use any method which leads to the same result as "eval"** using user inputs (CWE-77)

ESLint rule: ["no-implied-eval"](http://eslint.org/docs/rules/no-implied-eval).

### **2.14 App doesn't use any method of the ["childProcess"](https://nodejs.org/api/child_process.html) object** using user inputs (CWE-77)

ESLint rule: ["detect-child-process"](https://github.com/nodesecurity/eslint-plugin-security/blob/master/rules/detect-child-process.js).

### **2.15 Non-literals are not allowed in any method of the ["fs"](https://nodejs.org/api/fs.html) module** as a name (CWE-77)

ESLint rule: ["detect-non-fs-filename"](https://github.com/nodesecurity/eslint-plugin-security/blob/master/rules/detect-non-fs-filename.js).

### **2.16 Non-literals are not allowed in any "require"** (CWE-77)

ESLint rule: ["detect-non-literal-require"](https://github.com/nodesecurity/eslint-plugin-security/blob/master/rules/detect-non-literal-require.js).

### **2.17 Non-literals are not allowed in any regular expression** (CWE-77)

ESLint rule: ["detect-non-literal-regexp"](https://github.com/nodesecurity/eslint-plugin-security/blob/master/rules/detect-non-literal-regexp.js).

### **2.18 Protection against Cross-Site Request Forgery (CSRF)** is enabled ([CWE-352](http://cwe.mitre.org/data/definitions/352.html))

Deep explanation and demo included in the [section A8 of NodeGoat tutorial](http://nodegoat.herokuapp.com/tutorial/a8).

**Express**: [csurf](https://github.com/expressjs/csurf)

**Hapi**: [crumb](https://github.com/hapijs/crumb)

### **2.19 The [Content Security Policy](https://www.w3.org/TR/CSP/) setup is correct** (CWE-352)

**Express**: Use [Helmet](https://github.com/helmetjs/helmet) middleware (["csp" plugin](https://github.com/helmetjs/csp)).

**Hapi**: [blankie](https://github.com/nlf/blankie) module.

### **2.20 The "xframe" field is used**, to avoid [clickjacking](https://en.wikipedia.org/wiki/Clickjacking) ([CWE-693](http://cwe.mitre.org/data/definitions/693.html))

**Express**: Use [Helmet](https://github.com/helmetjs/helmet) middleware (["frameguard" plugin](https://github.com/helmetjs/frameguard)).

**Hapi**: Disabled by default, the framework supports it through the [route options](https://github.com/hapijs/hapi/blob/master/API.md#route-options) "security" ("xframe" field).

### **2.21 The app is adding headers to avoid the browsers sniffing mimetypes** ([CWE-430](http://cwe.mitre.org/data/definitions/430.html))

[CVE-2014-7939 Detail](https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2014-7939*)

**Express**: Use [Helmet](https://github.com/helmetjs/helmet) middleware (["nosniff" plugin](https://github.com/helmetjs/nosniff)).

**Hapi**: Disabled by default, the framework supports it through the [route options](https://github.com/hapijs/hapi/blob/master/API.md#route-options) "security" ("noSniff" field).


### **2.22 All uploaded files extension is checked the extension to be among the supported ones** ([CWE-434](http://cwe.mitre.org/data/definitions/434.html))

The core "path" module ["extname"](https://nodejs.org/api/path.html#path_path_extname_p) method is a simple option.

### **2.23 All unsafe paths names are restricted to a root dir** ([CWE-22](http://cwe.mitre.org/data/definitions/22.html))

>I want to restrict a path to something within a given root dir, I usually do something like this

(from [createWriteStream vulnerable to path traversal?](https://github.com/nodejs/node-v0.x-archive/issues/6157#issuecomment-23618929))

```javascript
var safePath = path.join(safeRoot, path.join('/', unsafePath));
```


## 3 Auditing and logging

### **3.1 All critical errors being logged**, at any level of debugging ([CWE-778](http://cwe.mitre.org/data/definitions/778.html))

### **3.2 An alert is generated when a critical error happens**

ie: email, Slack, etc. (CWE-778)

### **3.3 Different levels of debugging are supported** (CWE-778)

By importance ("warn", "info", etc.) and/or file ("*server*").

### **3.4 Change the debug level without restart**, ie: using environment variables (CWE-778)

### **3.5 All security-critical events are being logged** (CWE-778)

Use an independent logger or a debugger with a debug level as the default to print always. So we're using the term "logger" (or "logging") to refer to both from now.

["debug"](https://github.com/visionmedia/debug): Using it all logs will have the same structure and we can change what to see using the "DEBUG" environment variable. Moreover it's the same [used in Express](http://expressjs.com/es/guide/debugging.html).

### **3.6 All authentication activities (successful or not) are being logged**, at any level of debugging ([CWE-223](http://cwe.mitre.org/data/definitions/223.html), CWE-778)

### **3.7 All privilege changes (successful or not) are being logged**, at any level of debugging (CWE-223, CWE-778)

### **3.8 All administrative activities (successful or not) are being logged**, at any level of debugging (CWE-223, CWE-778)

ie: When you run a worker or standalone script.

### **3.9 All access to sensitive data are being logged**, at any level of debugging (CWE-223, CWE-778)

### **3.10 An alert is generated when a critical security event happens**, ie: email, Slack, etc. (CWE-223, CWE-778)

### **3.11 Anomalous conditions can be easily detected through the logs** ([CWE-779](http://cwe.mitre.org/data/definitions/779.html))

### **3.12 All errors are logged at the same level** (CWE-779)

Use log rotation and increate the limits until you consider it's safe. BTW the free plan of the wide used cloud services (over 48 h.) **is not enough**.

- ["Logging v. instrumentation"](http://peter.bourgon.org/blog/2016/02/07/logging-v-instrumentation.html)

### **3.13 An user entry is never written directly to the logs**

Look for another input (ie: session, DB) if possible or sanitize them before. The reason is to avoid an attacker impersonation and/or track covering ([CWE-117](http://cwe.mitre.org/data/definitions/117.html))

### **3.14 Logs never change the app behavior** (CWE-117)

### **3.15 Statistics are not taken from the logs** (CWE-117)

- To avoid a possible modification from attacker writing in them.
- Use secure tools to inspect automate the log inspection.

### **3.16 Logs do not include sensitive info** about users or environment. ([CWE-532](http://cwe.mitre.org/data/definitions/532.html), [CWE-215](http://cwe.mitre.org/data/definitions/215.html))

Log encryption (or part of them, ie: using a secure hash). Please refer to next section ("Cryptography").

### **3.17 Logs location is secure** ([CWE-533](http://cwe.mitre.org/data/definitions/533.html))

- We also need to store these server logs in a secure environment.
- A cloud service is comfortable here, this way you transfer the risk to them.
- If the log service has a management panel, a [2-factor authentication](https://en.wikipedia.org/wiki/Two-factor_authentication) mechanism is mandatory.


## 4 Cryptography

### **4.1 All routes which transmit sensitive info use SSL** ([CWE-523](http://cwe.mitre.org/data/definitions/523.html), [CWE-311](http://cwe.mitre.org/data/definitions/311.html), [CWE-319](http://cwe.mitre.org/data/definitions/319.html)).

Specially before the user authentication (ie: sending a password).

### **4.2 HTTP access is disabled for all routes which use SSL** (CWE-523, CWE-311, CWE-319)

**Express**: [express-force-ssl](https://github.com/battlejj/express-force-ssl)

- >Extremely simple middleware for requiring some or all pages to be visited over SSL.

**Hapi**: [hapi-require-https](https://github.com/bendrucker/hapi-require-https)

- >hapi http -> https redirection for servers behind a reverse proxy.

**Heroku** & SSL:

- Addon: [Expedited SSL](https://elements.heroku.com/addons/expeditedssl)
- HowTo: https://www.youtube.com/watch?v=OcyR7Yus4pc

### **4.3 The server only allows SSL connections** ([RFC 6797](https://tools.ietf.org/html/rfc6797))

**Express**: Use [Helmet](https://github.com/helmetjs/helmet) middleware (["hsts" plugin](https://github.com/helmetjs/hsts)).

**Hapi**: Disabled by default, the framework supports it through the [route options](https://github.com/hapijs/hapi/blob/master/API.md#route-options) "security" ("hsts" field).

### **4.4 The passwords, keys or certificates are not stored in clear files** ([CWE-312](http://cwe.mitre.org/data/definitions/312.html), CWE-319)

### **4.5 The passwords, keys or certificates are not stored in clear in the DB** (CWE-312, CWE-319)

A tool that can help to find them is [GitRob](https://github.com/michenriksen/gitrob).

### **4.6 Passwords, keys or certificates are not stored in a recoverable format** ([CWE-261](http://cwe.mitre.org/data/definitions/261.html), [CWE-257](http://cwe.mitre.org/data/definitions/257.html))

- Simply [**don't roll your own crypto!**](https://www.google.es/search?q=do+not+implement+your+own+crypto&oq=do+not+implement+your+own+crypto&aqs=chrome.0.69i59j69i64.2175j0j7&sourceid=chrome&ie=UTF-8#q=don%27t+roll+your+own+crypto), except for fun/learn. All frameworks include their own solutions to manage the login system and npm is full of them, just use one mature enough. Even we have other good standalone options, like the [Passwordless middleware](https://passwordless.net/).
- An interesting option is to avoid using passwords at all ([CWE-309](http://cwe.mitre.org/data/definitions/309.html)). Most of actual web applications connect user social accounts, so I think it's better to rely on them using a mature module ([Passport](http://passportjs.org/) or [Bell](https://github.com/hapijs/bell)). Better in one with mechanisms to figth against fake profiles.

### **4.7 The app is using bcrypt or pbkdf2 (or based library) to store the passwords securely** ([CWE-326](http://cwe.mitre.org/data/definitions/326.html))

- Remember, in general, MD5, SHA1, SHA256, SHA512, SHA-3, etc are not fully secure to other thing but check the integrity of the data. it's better to use [bcrypt](https://en.wikipedia.org/wiki/Bcrypt) or [pbkdf2](https://en.wikipedia.org/wiki/PBKDF2) based libraries.
- [How To Safely Store A Password](https://codahale.com/how-to-safely-store-a-password). The main advantage of pbkdf2 is to be platform independent.

### **4.8 The app is using secure crypto libraries** ([CWE-327](http://cwe.mitre.org/data/definitions/327.html))

- More specific:
  >Note that the upgrade to OpenSSL 1.0.1s in Node.js v0.12.11 removed internal SSLv2 support. The change in this release was originally intended for v0.12.11. The --enable-ssl2 command line argument now produces an error rather than being a no-op."
  - [Node v0.12.12 (LTS) release](https://nodejs.org/en/blog/release/v0.12.12)
- Use an updated version of Node.js.
- Refer to point 3.4 tips.
- Just in case, check [TLS Node.js core module](https://nodejs.org/api/tls.html) "secureProtocol" option which is being used.
- To exclude one cipher from the allowed ones use the option "cipher" in the [TLS module](https://nodejs.org/api/tls.html#tls_tls_createserver_options_secureconnectionlistener).

### **4.9 The app certificate respect the chain of trust** ([CWE-296](http://cwe.mitre.org/data/definitions/296.html), [CWE-295](http://cwe.mitre.org/data/definitions/295.html))

### **4.10 The app certificate match with the host** ([CWE-297](http://cwe.mitre.org/data/definitions/297.html), CWE-295, [CWE-322](http://cwe.mitre.org/data/definitions/322.html))

### **4.11 The app certificate has a valid expiration date** ([CWE-298](http://cwe.mitre.org/data/definitions/298.html), CWE-295)

### **4.12 The app certificate is not revoked** ([CWE-299](http://cwe.mitre.org/data/definitions/299.html), CWE-295)

### **4.13 All the points of this section are checked for any application SSL connections**

- Confirm the server is using a correct value for these options when requesting through the [TLS Node.js core module](https://nodejs.org/api/tls.html#tls_tls_connect_options_callback): "rejectUnauthorized" (default:true),"checkServerIdentity", "secureProtocol".
- A good to verify possible problems is ["sslyze"](https://github.com/iSECPartners/sslyze).
- A good option: [Let's Encryt](https://letsencrypt.org/about/), an open CA. Automatic HTTPS Certificates for Node.js.
  >Automatic live renewal.

  >On-the-fly HTTPS certificates for Dynamic DNS (in-process, no server restart).

  >Works with node cluster out of the box.

  >Free SSL (HTTPS Certificates for TLS) 90-day certificates.

**Express**: [letsencrypt-express](https://github.com/Daplie/letsencrypt-express).

**Hapi** and **Hapi** middleware: [letsencrypt-hapi](https://github.com/Daplie/letsencrypt-hapi).


## 5 Authentication and authorization

### **5.1 Neither passwords nor certificate keys are hard-coded** (or in separate file) in the source code of the application ([CWE-798](http://cwe.mitre.org/data/definitions/798.html))

- A tool that can help again is [GitRob](https://github.com/michenriksen/gitrob).
- The correct way to avoid hardcoding the credentials of the different microservices is to use [environment/application variables](https://devcenter.heroku.com/articles/config-vars). Only the one in charge of the deployment should have access to get/set them through a secure channel.

### **5.2 The password recovery mechanism is strong** ([CWE-640](http://cwe.mitre.org/data/definitions/640.html))

- Please, refer to the point 4.6 of this document, just use a mature option.
- An important specific check is to validate the security of the generated token sent to the user email.

### **5.3 The users are forced to enter a strong password** ([CWE-521](http://cwe.mitre.org/data/definitions/521.html))

- We should ask them for a new better option if it doesn't reach our expectations.
- Please, refer to the point 4.6, use a mature solution.
- By the way we have [some good modules](https://github.com/nowsecure/owasp-password-strength-test) to check the strength of the passwords set by the users.

### **5.4 The users are forced to change the password in a regular basis** ([CWE-262](http://cwe.mitre.org/data/definitions/262.html))

Implement it manually, no serious solution found out there to help with this.

### **5.5 The application detects and blocks any possible brute-force attack** ([CWE-307](http://cwe.mitre.org/data/definitions/307.html))

### **5.6 The block expires after a period of time** (CWE-307)

### **5.7 The application support a blacklist of IP address to block** (CWE-307)

### **5.8 The application can manually block an IP address** (CWE-307)

### **5.9 The application can manually unblock an IP address** (CWE-307)

### **5.10 The application can manually block a country** (CWE-307)

### **5.11 The application can manually unblock a country** (CWE-307)

- [node-ratelimiter](https://github.com/tj/node-ratelimiter): It uses Redis, supports reset.
- To locate an IP address: [node-geoip](https://github.com/bluesmoon/node-geoip), but there're [multiple options](https://www.npmjs.com/browse/keyword/geolocation).

**Express** middlewares:

- [node-ipgeoblock](https://github.com/ilich/node-ipgeoblock): "blacklist of IPs, the blacklist of countries or the whitelist of countries.""
- [express-limiter](https://github.com/ded/express-limiter): Built on Redis, whitelists support.
- [express-brute](https://github.com/AdamPflug/express-brute): Support multiples stores, "increasing the delay with each request in a fibonacci-like sequence".

**Hapi**:

- [hapi-ratelimit](https://github.com/creativelive/hapi-ratelimit): Built on Redis.
- Manual implementation: https://gist.github.com/whisher/d6e3db7c11d632720133

### **5.12 All requests came through an authentication middleware** ([CWE-284](http://cwe.mitre.org/data/definitions/284.html))

### **5.13 All new requests (not login users) have the least privilege possible** ([CWE-272](http://cwe.mitre.org/data/definitions/272.html), CWE-284)

### **5.14 All the info taken in account for authentication is taken from trusted sources** (CWE-284)

- A common example is to get an user ID from "req.params.userId" (which could be manipulated directly in the request payload) instead "req.session.userId".
- Deep explanation and demo included in the [section A4 of NodeGoat tutorial](http://nodegoat.herokuapp.com/tutorial/a4).

### **5.15 The app doesn't expose actual database keys as part of the access links** (CWE-284)

- The quickest and most secure option here is to use a well-tested framework to implement this part, ie: [Passport](http://passportjs.org/).
- Map each internal ID to a shorter (and more beautiful) one before sending it to the client and use it for the whole communication.
  - ["shortid"](https://github.com/dylang/shortid): "Short id generator. Url-friendly. Non-predictable. Cluster-compatible.".
- Deep explanation and demo included in the [section A7 of NodeGoat tutorial](http://nodegoat.herokuapp.com/tutorial/a7).

### **5.16 The app doesn't use URL redirection** ([CWE-601](http://cwe.mitre.org/data/definitions/601.html))

### **5.16.1 If URL redirection is used, it doesn’t involve user parameters to calculate the destination**

- In general, avoid using [URL redirection](https://en.wikipedia.org/wiki/URL_redirection).
- It is recommended that any destination parameters is a mapped value, instead of the actual URL (or a part).
- Deep explanation and demo included in the [section A10 of NodeGoat tutorial](http://nodegoat.herokuapp.com/tutorial/a10).


## 6 Session

### **6.1 The method to generate session IDs is strong** ([CWE-6](http://cwe.mitre.org/data/definitions/6.html))

The basic idea is to use a secure method (random and enough length) to generate each user session identifier. The best option, as always, is to use a mature option.

**Express**:

- A secure method is used (["uid-safe"](https://github.com/crypto-utils/uid-safe) module) by default in the ["express-session"](https://github.com/expressjs/session#compatible-session-stores) middleware.
- Moreover the user can define his own one using the ["genid"](https://github.com/expressjs/session#genid) option.

**Hapi**:

- The methods [server.cache](http://hapijs.com/api#servercacheoptions) includes the method "generateFunc" to specify your own algorithm.
- Another of the most used options (["hapi-auth-basic"](https://github.com/hapijs/hapi-auth-basic), ["hapi-auth-cookie"](https://github.com/hapijs/hapi-auth-cookie) and ["yar"](https://github.com/hapijs/yar)).
- Neither of them don't include a method to generate it by default. So the user have to implement his own using a secure alternative (again, like "uid-safe").

### **6.2 The session is destroyed on every user logout** ([CWE-613](http://cwe.mitre.org/data/definitions/613.html))

### **6.3 The session is destroyed after an absolute session timeout** (CWE-613)

### **6.4 The session is destroyed after an iddle session timeout** (CWE-613)

### **6.5 In all cases the sessions is also dropped from persistent storage** (ie: Redis) (CWE-613)

- Inactive sessions should be destroyed automatically when the user is inactive from an amount of time. There are multiple JavaScript libraries [to achieve it from the client-side](https://www.npmjs.com/search?q=idle).

**Express**: The [connect-redis](https://github.com/tj/connect-redis) library supports the "ttl" options to set the session expiration.

**Hapi**:

- The server side caching is a built-in feature. It includes the method ["server.state"](http://hapijs.com/api#serverstatename-options) also includes the option "ttl". Moreover it also includes the ["server.cache"](http://hapijs.com/api#servercacheoptions) one which supports the following options:
  - >expiresIn - relative expiration expressed in the number of milliseconds since the item was saved in the cache. Cannot be used together with expiresAt.
  - >expiresAt - time of day expressed in 24h notation using the 'HH:MM' format, at which point all cache records expire. Uses local time. Cannot be used together with expiresIn.
  - >staleIn - number of milliseconds to mark an item stored in cache as stale and attempt to regenerate it when generateFunc is provided. Must be less than expiresIn.
  - >staleTimeout - number of milliseconds to wait before checking if an item is stale.
- Another important check is to confirm (to avoid pollution and future space problems) that the session is also destroyed in the permanent storage (ie: Redis).

**Express**: The ["express-session"](https://github.com/expressjs/session#compatible-session-stores) middleware includes the methods ["Session.Destroy"](https://github.com/expressjs/session#sessiondestroy) and ["store.destroy"](https://github.com/expressjs/session#storedestroysid-callback) (persistent) to manage it in a consistent way.

**Hapi**: Native server cache manages it correctly through the supported storages via [catbox](http://hapijs.com/tutorials/caching).

### **6.6 The server generate a new session ID after an user authentication** ([CWE-384](http://cwe.mitre.org/data/definitions/384.html))

### **6.7 The server generate a new session ID after an user privilege level change** (CWE-384)

### **6.8 The server generate a new session ID after an encryption level change** (CWE-384)

**Express**: The "express-session" middleware offers the method ["regenerate"](https://github.com/expressjs/session#sessionregenerate) to make it easier.

**Hapi**: here we have the method "generateFunc". Check point 6.1 tips to know more.

### **6.9 All cookies have a not default name**

**Express**: The "express-session" middleware offers the [option "name"](https://github.com/expressjs/session#cookie-options).

**Hapi**: Cookies enabled by default, the option "name" in the method ["server.state"](https://github.com/hapijs/hapi/blob/master/API.md#serverstatename-options).


### **6.10 All cookies use the "secure" flag**, to set them only under HTTPS. ([CWE-614](http://cwe.mitre.org/data/definitions/614.html))

**Express**: The "express-session" middleware offers the [option "secure"](https://github.com/expressjs/session#cookie-options).

**Hapi**: Cookies enabled by default, the option "isSecure" in the method ["server.state"](https://github.com/hapijs/hapi/blob/master/API.md#serverstatename-options).


### **6.11 All cookies use the "HttpOnly" flag**, to ensures they are only sent over HTTP(S), not client JavaScript. ([CWE-79](http://cwe.mitre.org/data/definitions/79.html))

**Express**: The "express-session" middleware offers the [option "httpOnly"](https://github.com/expressjs/session#cookie).

**Hapi**: Cookies enabled by default, the option "isHttpOnly" in the method ["server.state"](https://github.com/hapijs/hapi/blob/master/API.md#serverstatename-options).

### **6.12 All cookies are signed with a secret** ([CWE-565](http://cwe.mitre.org/data/definitions/565.html))

**Express**: The "express-session" middleware offers the [option "secret"](https://github.com/expressjs/session#secret).

**Hapi**: Cookies enabled by default, the option "sign" (for "integrity" and/or with password) in the method ["server.state"](https://github.com/hapijs/hapi/blob/master/API.md#serverstatename-options).


## 7 Environment

### **7.1 The app has a [CI](https://en.wikipedia.org/wiki/Continuous_integration) system** ([CWE-439](http://cwe.mitre.org/data/definitions/439.html), [CWE-701](http://cwe.mitre.org/data/definitions/701.html), [CWE-656](http://cwe.mitre.org/data/definitions/656.html))

[Travis](https://docs.travis-ci.com/user/getting-started/) and [Heroku's GitHub integration](https://devcenter.heroku.com/articles/github-integration#automatic-deploys) is a comfortable option.

### **7.2 The coverage for the tests is enough**

[Istanbul](https://github.com/gotwarlost/istanbul) is a well-known option.

### **7.3 Check for dependencies with known vulnerabilities** is included in the CI

["nsp"](https://github.com/nodesecurity/nsp) automates it for you.

### **7.4 Check for non updated dependencies** is included in the CI

["npm-check-updates"](https://github.com/nodesecurity/npm-check-updates) automates it for you.

### **7.5 Check for insecure regular expressions** is included in the CI. ([CWE-185](https://cwe.mitre.org/data/definitions/185.html))

Use this ESLint rule : ["detect-unsafe-regex"](https://github.com/nodesecurity/eslint-plugin-security/blob/master/rules/detect-unsafe-regex.js).

### **7.6 [Semantic versioning](http://semver.org/) is used correctly**

- To support the last version of the dependencies.
- Use the tilde and caret correctly in the ["package.json"](https://docs.npmjs.com/files/package.json) file.
  - https://nodesource.com/blog/semver-tilde-and-caret

### **7.7 Dependency versions are blocked in production** to avoid surprises

The solution is to use ["npm shrinkwrap"](https://docs.npmjs.com/cli/shrinkwrap).

### **7.8 There's a npm task to install dependencies ignoring the scripts** ([VU#319816](https://www.kb.cert.org/vuls/id/319816))

- The solution is to block them. So it's better to have an npm/Grunt/Gulp task to do it: [Package install scripts vulnerability](http://blog.npmjs.org/post/141702881055/package-install-scripts-vulnerability)

### **7.9 The user inputs are fuzzed in a regular basis**

- A library to help: [Surku](https://github.com/attekett/Surku)
- Use external libraries like [ZAP](https://www.owasp.org/index.php/OWASP_Zed_Attack_Proxy_Project) ([Node.js bindings](https://github.com/zaproxy/zaproxy/tree/develop/nodejs/api/zapv2)).

### **7.10 The whole infrastructure is secured** ([CWE-15](http://cwe.mitre.org/data/definitions/15.html), [CWE-656](http://cwe.mitre.org/data/definitions/656.html))

- Attackers should use the easiest way to break in, so we also need to secure the OS where the service is running.
- Cloud deployment platforms are a good option to minimize this risk.
- In case you prefer to manage your own OS a good tool to check automatically its security in an easy way is [Lynis](https://cisofy.com/lynis/).

### **7.11 Application with minimal privileges** ([CWE-250](http://cwe.mitre.org/data/definitions/250.html))

- All involved microservices should respect this rule.
- Again a comfortable solution is to use a cloud deployment environment to avoid this risk.

### **7.12 The team in educated on security**

- Sending them to conferences is a fun way to achieve it with good results.
- Official advisories: https://groups.google.com/forum/#!forum/nodejs-sec.
- It's good to watch the Github repositories for notifications to be informed if any vulnerabilities are discovered in the package in future.

### **7.13 The team doesn't use company devices for personal stuff**

### **7.14 The app respect some written security requirements**

Have in account that sometimes we need to assume risks.

### **7.15 The application has an incident plan**

- Which includes how to recover from the worst case scenarios (ie: Amazon -> Heroku, GitHub down).

### **7.16 A design review is performed in a regular basis**

Drop not needed stuff as much ass possible, [keep it simple](https://en.wikipedia.org/wiki/KISS_principle). Less surface exposure -> more secure.

### **7.17 A security code audit is performed regular basis** (internal and external). ([CWE-702](http://cwe.mitre.org/data/definitions/702.html))

Apply this methodology ;).

### **7.18 A web specific penetration test is performed in a regular basis** (internal and external)

**Internal**: To know how to conduct a pentest it's not our responsibility as Backend developers. But of course we know about web technologies so it's something we can do for sure. We can learn at the same time we mitigate some of the vulnerabilities that are going to be found in the next step (they always find stuff:)). The best point to start (and the same the professionals use) is the [OWASP Testing guide](https://www.owasp.org/images/5/52/OWASP_Testing_Guide_v4.pdf). Some free tools which can help to automate it are: [ZAP](https://www.owasp.org/index.php/OWASP_Zed_Attack_Proxy_Project), [sqlmap](http://sqlmap.org/), [Skipfish](https://github.com/spinkham/skipfish), [w3af](http://w3af.org/), [Nikto](https://www.cirt.net/Nikto2).

**External**: Again just hire a proper company.

## License

[<img src="http://mirrors.creativecommons.org/presskit/buttons/88x31/png/by-nc-sa.eu.png" height="40" alt="CC BY-NC SA 3.0">](https://creativecommons.org/licenses/by-nc-sa/3.0/)

### Author

- Jesús Pérez
- jesusprubio@fsf.org
- [@jesusprubio](https://twitter.com/jesusprubio)
