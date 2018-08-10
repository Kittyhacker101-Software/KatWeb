<img src="https://kittyhacker101.tk/KatWeb.png" alt="KatWeb - A modern and lightweight webserver designed for the modern web."></img> 

## Getting KatWeb
To download KatWeb, you can either download a compiled release from the [releases page](https://github.com/kittyhacker101/KatWeb/releases), or compile KatWeb from the source code in the repository (**not recommended, code in the repository is not suitable for production use**).

### Linux Packages
- Arch Linux users can install the [katweb](https://aur.archlinux.org/packages/katweb/) AUR package.
- Debian/Ubuntu packages are currently in development.
- Snapcraft packages are currently in development.

## Using KatWeb
After you have extracted the compressed release, you can run the right build for your platform.
The root folder for serving files is /html/, the configuration is /conf.json.
Documentation for KatWeb can be found in the [KatWeb Wiki](https://github.com/kittyhacker101/KatWeb/wiki).

### Running as root
Running KatWeb as root is not recommended for security reasons. You can allow KatWeb to use to ports below 1024 on Linux by using this command: `sudo setcap cap_net_bind_service=+ep ./katweb-linux-*`

### Additional Info
Want to discuss KatWeb, or have any questions? Join [KatWeb's Discord server](https://discord.gg/Wy2kHBg).

## Features
- TLS 1.2 Support (v1.0+)
- HSTS Support (v1.0+)
- JSON Config Files (v1.0+)
- HTTP/2 and Keep-Alive (v1.8.1+, partial support since v1.0)
- Brotli Compression Support (v1.9.5+)
- GZIP Compression Support (v1.5.4+, partial support since v1.0)
- Let's Encrypt Integration (v1.9+)
- Dynamic Serving (v1.0+)
- Multiple logging formats (v1.10.1+)
- Password Protected Directories (v1.0+)
- HTTP Reverse Proxy (v1.2.7+)
- Websocket Reverse Proxy (v1.8+)
- Material Design Directory Listings (v1.6+)
- Material Design Error Pages (v1.9.1+)
- Easy to use Browser Control Panel (v1.10+)
