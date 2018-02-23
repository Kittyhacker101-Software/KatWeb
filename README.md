## KatWeb
Welcome to KatWeb!
KatWeb is a simple static file HTTPS server designed for the 21st century.
This program is used in production on the kittyhacker101.tk servers!
Note : It is reccomended to download a release of the software, instead of building the latest code in the repository.

## File System Structure
- /KatWeb/cache/ - Simple HTTP Cache.
- /KatWeb/html/ - Document root of server.
- /KatWeb/ssl/ - Server HTTPS certificates.
- /KatWeb/conf.json - Server config file.

## Simple HTTP Cache
KatWeb comes with a built in HTTP cache that can be useful for sending files from other websites through your server!
Text files containing URLs in the cache folder will be downloaded and a cached version will be stored. You can then access the file through /[cache folder]/filename(without the .txt extention).

## Simple HTTP Reverse-Proxy
KatWeb comes with a built in HTTP reverse-proxy which allows sending data from other web servers! Once setup, an existing web server can be accessed through the proxy folder!

## Dynamic Content Control
KatWeb comes with a built in system to serve different content depending on various factors.
 - Folders in /KatWeb with a domain name will serve different content for that domain.
 - Files named passwd and containing the format [username]:[password] can be used to protect files
 - Files containing a URL and .redir allow permanent HTTP redirects.

## Config Options
- keepAliveTimeout - The max length of time a keep-alive connection can stay open in seconds. Setting this to zero will disable keep-alive.
- cachingTimeout - How many hours you want the files sent by the web-server to be cached in the browser. Setting this to zero will disable caching.
- streamTimeout - The max length of time an HTTP connection can stay open in seconds. Setting this higher than 20 is reccomended for sites which transfer large files.
- logging - Logging of sucessfully handled requests. It is reccomended to turn this off if you recieve a large number of web requests going to your server.
- hsts - Forces all browsers to use HTTPS for your website. Requires a valid HTTPS cert.
  * enabled - If HSTS should be enabled, requires a valid HTTPS cert.
  * mixedssl - Uses the Alt-Svc header to tell browsers that an SSL connection is available.
  * includeSubDomains - If HSTS should effect subdomains, must be enabled for preload to work.
  * preload - If your site's HSTS rule should be preloaded into the browser's HSTS preload list. Once you are in the preload list, you can't get out of it easily!
- protect - Prevents other web-sites from stealing your content in various ways.
- gzip - HTTP compression for files.
  * enabled - If gzip should be enabled. 
  * level - Compression level for gzip (Between 1 and 9, 4-6 is reccomended)
- hcache - Simple HTTP Cache.
  * enabled - If Simple HTTP Cache should be enabled.
  * location - Location of the HTTP Cache's folder
  * updates - How often the HTTP Cache should update it's files in minutes.
- proxy - Simple HTTP Proxy.
  * enabled - If Simple HTTP Proxy should be enabled.
  * location - URL path of the HTTP Proxy. 
  * host - The url of the location being proxied.
- name - The server name sent in the "Server" HTTP Header.
- httpPort - The port for the HTTP server to run on.
- sslPort - The port for the HTTPS server to run on.

Changing conf options requires a server restart to take effect.

## Optimizing for Maximum Peformance
To get the maximum peformance out of KatWeb, here's some optimization tips :
- Disable logging in the config. This can help speed up websites with large numbers of users by 2x in most cases.
- Use x86_64 Linux. The x86_64 version of KatWeb is the most optimized, and KatWeb works more reliably on Linux systems.
- Use only physical cores, and disable hyperthreading on CPUs with high clock speeds. On some CPUs, this can improve peformance by more than 2x, but it doesn't always help peformance. This will vary from CPU to CPU, so it may help peformance on one CPU, but can hurt peformance on others. When in doubt, test it on your hardware, and see how it impacts peformance.
- Use GZIP when there is limited bandwidth. The overhead of KatWeb's Gzip is quite small, and it will help if bandwidth is your main limiting factor.
- Use reverse proxing as little as possible, as it will add more latency to web requests.

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
- Material Design Directory Listings
