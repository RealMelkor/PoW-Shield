# PoW Shield

A nginx module to add a proof-of-work challenge before accessing a page.

![pic0](./img/img.webp)

## Build

To build this module you will need to download nginx source code first.
Clone Pow Shield repository outside of the nginx source folder.
In the nginx source code directory uses the command :

./auto/configure --add-dynamic-module=[absolute path to PoW-Shield repo]

This will build PoW Shield as a dynamically loadable module.
If you want to build the module for a pre-compiled nginx server, you will need
to get the source code of the same version as the pre-built nginx.
You will also need to compile it with the same flags. To see with which flags
a nginx binary was built with, use the command 'nginx -V'.

## Configuration

In your nginx configuration file, add 'powshield "on";' to a server or a location.
The protection can also be disabled for specific URLs with 'powshield "off";'

```nginx
server {
    listen      80;
    server_name localhost;

    root html;

    powshield "restricted";
    location /static {
        powshield off;
    }

    location / {
        index   index.html index.htm;
    }
}
```

If the module was built as a dynamic module, you will need to add at the top of
your nginx configuration file the following line :

```nginx
load_module "/path/to/ngx_http_powshield_module.so";
```
