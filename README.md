<img src="https://kittyhacker101.tk/KatWeb.png" alt="KatWeb - A modern and lightweight webserver designed for the modern web."></img> 

## Getting KatWeb
To download KatWeb, you can either download a compiled release from the [releases page](https://github.com/kittyhacker101/KatWeb/releases), or compile KatWeb from the source code in the repository (**not recommended, code in the repository is not suitable for production use**).

### Linux Packages
- Arch Linux users can install the [katweb](https://aur.archlinux.org/packages/katweb/) AUR package.
- Debian/Ubuntu packages are currently in development.

## Using KatWeb
After you have extracted the compressed release, you can run the right build for your platform.
The root folder for serving files is /html/, the configuration is /conf.json.
Documentation for KatWeb can be found in the [KatWeb Wiki](https://github.com/kittyhacker101/KatWeb/wiki).

### Running as root
Running KatWeb as root is not recommended for security reasons. You can allow non-root processes to bind to ports below 1024 on Linux by using this command: `sudo setcap cap_net_bind_service=+ep ./katweb-linux-*`

## Features
- TLS 1.2 Support (with partial support for TLS 1.3 draft #22)
- HSTS Support
- JSON Config Files
- HTTP/2 and Keep-Alive
- HTTP Compression
- Let's Encrypt Integration
- Dynamic Serving
- Modern Default Pages
- Logging to Console
- Password Protected Directories
- HTTP Reverse Proxy
- Websocket Reverse Proxy
- Material Design Directory Listings
- Material Design Error Pages
