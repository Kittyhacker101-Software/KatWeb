# KatWeb
Welcome to KatWeb HTTP Server!
KatWeb is a modern HTTPS server designed for the 21st century.
Made in 100% Golang, currently a work in progress.

# File System Structure
>/html/ - Document root of server.
>/ssl/ - Server HTTPS certificates.
>/error/ - Server error pages.
>/conf.json - Server config file.

# Config Options
- keepAliveTimeout - The max length of time a keep-alive connection can stay open in seconds. Must be greater than zero!
- cachingTimeout - How many hours you want the files sent by the web-server to be cached in the browser. Setting this to zero will disable caching.
- hsts - Forces all browsers to use HTTPS for your website. Requires a valid HTTPS cert.
  * enabled - If HSTS should be enabled, requires a valid HTTPS cert.
  * includeSubDomains - If HSTS should effect subdomains, must be enabled for preload to work.
  * preload - If your site's HSTS rule should be preloaded into the preload list. Once you are in the preload list, you can't get out of it easily!
- https - If you wish to have an encrypted connection.
- nosniff - Prevents web browsers from sniffing away content types.
- sameorigin - Prevents other web-sites from stealing your content using iframes.
- gzip - HTTP compression for files. Keep this on unless you are attempting to host on a Raspberry Pi Zero :P
- dynamicServing - Serve content differently by domain. If a folder for that domain is not present, it defaults to /html/

Changing conf options requires a server restart to take effect.
