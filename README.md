## KatWeb
Welcome to KatWeb HTTP Server!
KatWeb is a static file HTTPS server designed for the 21st century.
This program is used in production on the kittyhacker101.tk servers!

## File System Structure
- /cache/ - Simple HTTP Cache.
- /html/ - Document root of server.
- /ssl/ - Server HTTPS certificates.
- /conf.json - Server config file.

## Simple HTTP Cache
KatWeb comes with a built in HTTP Cache that can be useful for sending files from other websites through your server!
- To use it, you create a file called [filename].txt in the /cache folder.
  * Example : If you want to make your file called example.svg, you make a file named example.svg.txt
- Then, you put the link to the original source in the txt file.
  * Example : If you want meow.png to show a nyan cat gif, you put the link to the gif (http://kittyhacker101.tk/Static/Card.svg) in example.svg.txt.
- Now, you can view your stuff through /cache!
  * Example : To see example.svg, you can open localhost/cache/example.svg.txt in your browser.

## Dynamic Content Control
KatWeb comes with a built in system to serve different content depending on various factors.
- You can use this to send content differently by domain!
  * Just create a new folder with the domain name in the / folder (not /html, the layer below it). Then put your content in there! This requires a restary to take effect!
- You can use this to password protect folders!
  * Just create a file in the folder you want to protect, and name it passwd. Then put [username]:[password] in your file (Example : "admin:passwd")!
 - You can use this to do HTTP redirects!!
   * Just create a file which ends in .redir! Then put your link in there, and you can access it without the .redir (Example : meme.txt.redir => meme.txt)

## Config Options
- keepAliveTimeout - The max length of time a keep-alive connection can stay open in seconds. Setting this to zero will disable keep-alive.
- cachingTimeout - How many hours you want the files sent by the web-server to be cached in the browser. Setting this to zero will disable caching.
- hsts - Forces all browsers to use HTTPS for your website. Requires a valid HTTPS cert.
  * enabled - If HSTS should be enabled, requires a valid HTTPS cert.
  * includeSubDomains - If HSTS should effect subdomains, must be enabled for preload to work.
  * preload - If your site's HSTS rule should be preloaded into the browser's HSTS preload list. Once you are in the preload list, you can't get out of it easily!
- protect - Prevents other web-sites from stealing your content in various ways.
- gzip - HTTP compression for files.
- hcache - Simple HTTP Cache.
  * enabled - If Simple HTTP Cache should be enabled.
  * updates - How often the HTTP Cache should update it's files in seconds.
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
