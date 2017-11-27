## KatWeb
Welcome to KatWeb HTTP Server!
KatWeb is a simple static file HTTPS server designed for the 21st century.
This program is used in production on the kittyhacker101.tk servers!
Note : Putting KatWeb behind a CDN or reverse proxy is recommended for production setups, but not required.

## File System Structure
- /KatWeb/cache/ - Simple HTTP Cache.
- /KatWeb/html/ - Document root of server.
- /KatWeb/ssl/ - Server HTTPS certificates.
- /KatWeb/conf.json - Server config file.

## Simple HTTP Cache
KatWeb comes with a built in HTTP cache that can be useful for sending files from other websites through your server!
Text files containing URLs in the cache folder will be downloaded and a cached version will be stored. You can then access the file through /[cache folder]/filename(without the .txt extention).

## Simple HTTP Reverse-Proxy
KatWeb comes with a built in HTTP reverse-proxy which allows sending data from other web servers! Once setup, an existing web server can be accessed through the proxy folder (Note : A proxy folder must exist on the existing server for content to be served)

## Dynamic Content Control
KatWeb comes with a built in system to serve different content depending on various factors.
 - Folders in /KatWeb with a domain name will serve different content for that domain.
 - Files named passwd and containing the format [username]:[password] can be used to protect files
 - Files containing a URL and .redir allow permanent HTTP redirects.

## Config Options
- keepAliveTimeout - The max length of time a keep-alive connection can stay open in seconds. Setting this to zero will disable keep-alive.
- cachingTimeout - How many hours you want the files sent by the web-server to be cached in the browser. Setting this to zero will disable caching.
- streamTimeout - The max length of time an HTTP connection can stay open in seconds. Setting this higher than 20 is reccomended for sites which transfer large files.
- hsts - Forces all browsers to use HTTPS for your website. Requires a valid HTTPS cert.
  * enabled - If HSTS should be enabled, requires a valid HTTPS cert.
  * mixedssl - Uses the Alt-Svc header to tell browsers that an SSL connection is available.
  * includeSubDomains - If HSTS should effect subdomains, must be enabled for preload to work.
  * preload - If your site's HSTS rule should be preloaded into the browser's HSTS preload list. Once you are in the preload list, you can't get out of it easily!
- protect - Prevents other web-sites from stealing your content in various ways.
- gzip - HTTP compression for files.
  * enabled - If gzip should be enabled.
  * level - Compression level for gzip (Between 1 and 9)
- hcache - Simple HTTP Cache.
  * enabled - If Simple HTTP Cache should be enabled.
  * location - Location of the HTTP Cache's folder
  * updates - How often the HTTP Cache should update it's files in minutes.
- proxy - Simple HTTP Proxy.
  * enabled - If Simple HTTP Proxy should be enabled.
  * location - URL path of the HTTP Proxy. 
  * type - If the server being proxied is using HTTP or HTTPS.
  * host - The port and domain of the server being proxied.
- name - The server name sent in the "Server" HTTP Header.
- httpPort - The port for the HTTP server to run on.
- sslPort - The port for the HTTPS server to run on.

Changing conf options requires a server restart to take effect.

## Features
- SSL Support
- HSTS Support
- JSON Config Files
- HTTP/2 and Keep-Alive
- HTTP Compression
- Dynamic Serving
- Modern Default Pages
- Logging to Console
- Basic HTTP Cache
- Password Protected Directories
- Custom Redirects
- Opportunistic Encryption
- HTTP Reverse Proxy
