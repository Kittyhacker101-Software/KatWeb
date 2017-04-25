## KatWeb
Welcome to KatWeb HTTP Server!
KatWeb is a modern HTTPS server designed for the 21st century.
Made in 100% Golang, currently in very early beta.
**PLEASE DO NOT USE THIS IN PRODUCTION, ITS NOT FINISHED!!!**

## File System Structure
- /html/ - Document root of server.
- /ssl/ - Server HTTPS certificates.
- /error/ - Server error pages.
- /conf.json - Server config file.

## Config Options
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
- cacheStruct - Caches Dynamic Serving folder structure, enabling this will require you to restart the server for Dynamic Serving folders to be added/removed.
- silent - Don't log anything. Also disables most error checking, so be careful!
- name - The server name sent in the "Server" HTTP Header.

Changing conf options requires a server restart to take effect.

## Current and Planned Features 
- [x] SSL Support
- [x] HSTS Support
- [x] JSON Config Files
- [x] HTTP/2 and Keep-Alive
- [x] Automatic HTTP Compression
- [x] Dynamic Serving
- [x] Modern Default Pages
- [x] Logging to Console
- [ ] RAM Caching (Partially Done)
- [ ] Password Protected Directories
- [ ] Custom Redirects
- [ ] PHP Support (Possible)
- [ ] QUIC Support (Possible)

Note that more features are coming soon, and not all features in this list will be implemented.
