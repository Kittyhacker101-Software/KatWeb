<img src="https://kittyhacker101.tk/KatWeb.png" alt="KatWeb - A modern and lightweight webserver designed for the modern web."></img> 

## Getting KatWeb
You can download a packaged release of KatWeb from the [releases page](https://github.com/kittyhacker101/KatWeb/releases). **WARNING: KatWeb has reached the end of it's effective lifespan, and will only receive critical security patches if major security flaws are discovered. It is effectively discontinued, and should not be used in development or production environments.** Consider using [KatWebX](https://github.com/kittyhacker101/KatWebX) instead.

### Linux Packages
- Arch Linux users can install the [katweb](https://aur.archlinux.org/packages/katweb/) AUR package.

## Using KatWeb
After you have extracted the compressed release, you can run the right build for your platform.
The root folder for serving files is /html/, the configuration is /conf.json.
Documentation for KatWeb can be found on the [KatWeb Wiki](https://github.com/kittyhacker101/KatWeb/wiki).

### Running as root
Running KatWeb as root is not recommended for security reasons. You can allow KatWeb to use to ports below 1024 on Linux by using this command: `sudo setcap cap_net_bind_service=+ep ./katweb-linux-*`

### Additional Info
- Want to help fund KatWeb's development? Consider donating to the Bitcoin address `1KyggZGHF4BfHoHEXxoGzDmLmcGLaHN2x2`.
- Found a bug in KatWeb? Report it [here](https://github.com/kittyhacker101/KatWeb/issues).

## Features
- High Peformance TLS 1.2 (v1.0+)
- Let's Encrypt Integration (v1.9+)
- High Peformance HTTP/2 (v1.0+)
- GZIP Compression Support (v1.0+)
- Brotli Compression Support (v1.9.5+)
- High Peformance Reverse Proxy (v1.2.7+)
- Websocket Reverse Proxy (v1.8+)
- Regex-Based Redirect Support (v1.10.1+)
- Simple JSON-based configuration (v1.0+)
- Simple Browser Control Panel (v1.10+)
- Virtual Hosting Support (v1.0+)
- Password Protection Support (v1.0+)
- Multiple Logging Formats (v1.10.1+)
- Modern Directory Listings (v1.6+)
- Modern Error Pages (v1.9.1+)
