# Subscribe2config
Generate [v2ray configuration](https://www.v2fly.org/config/overview.html) ased on subscription information.

## Help

```
usage: subscribe2config.py [-h] -i INPUT [-o OUTPUT] [--multi-files] [--patch [PATCHS ...]]

options:
  -h, --help            show this help message and exit
  -i INPUT, --input INPUT
                        The input, can be subscribe url, file or share url.
  -o OUTPUT, --output OUTPUT
                        Output file or folder.
  --multi-files         Generate a separate file for each entry.
  --patch [PATCHS ...]  <JSON_PATH>=<VALUE>. Patch v2ray config by JsonPath.
```

## Examples

### `vmess://`, `vless://`, `trojan://`, `ss://` or `socks://` url

```sh
python3 ./subscribe2config.py -i "trojan://password@example:32000?security=tls&type=tcp&headerType=none#test-server"
```

```json
{
    "outbounds": [
        {
            "protocol": "trojan",
            "tag": "test-server",
            "settings": {
                "servers": [
                    {
                        "address": "example",
                        "port": 32000,
                        "password": "password"
                    }
                ]
            },
            "streamSettings": {
                "network": "tcp",
                "security": "tls",
                "tlsSettings": {
                    "allowInsecure": false
                },
                "tcpSettings": {
                    "type": "none"
                }
            }
        }
    ]
}
```

### Subscribe Url

```sh
python3 ./subscribe2config.py -i "https://example.com/subscribe"
```

```json
{
    "outbounds": [
        {
            "protocol": "trojan",
            "tag": "server1.example.com",
            "settings": {
                "servers": [
                    {
                        "address": "server1.example.com",
                        "port": 443,
                        "password": "password",
                        "level": null,
                        "email": null
                    }
                ]
            },
            "streamSettings": {
                "network": "ws",
                "security": "tls",
                "tlsSettings": {
                    "allowInsecure": false
                },
                "wsSettings": {
                    "path": "/trojan"
                }
            }
        },
        {
            "protocol": "trojan",
            "tag": "server2.example.com",
            "settings": {
                "servers": [
                    {
                        "address": "server2.example.com",
                        "port": 443,
                        "password": "password"
                    }
                ]
            },
            "streamSettings": {
                "network": "ws",
                "security": "tls",
                "tlsSettings": {
                    "allowInsecure": false
                },
                "wsSettings": {
                    "path": "/trojan",
                }
            }
        }
    ]
}
```

## Custom Patch

```sh
python3 ./subscribe2config.py \
    -i "trojan://password@example:32000?security=tls&type=tcp&headerType=none#test-server" \
    --patch '$.outbounds..streamSettings.sockopt={"tproxy":"tproxy","mark":255}'
```

```json
{
    "outbounds": [
        {
            "protocol": "trojan",
            "tag": "test-server",
            "settings": {
                "servers": [
                    {
                        "address": "example",
                        "port": 32000,
                        "password": "password"
                    }
                ]
            },
            "streamSettings": {
                "network": "tcp",
                "security": "tls",
                "tlsSettings": {
                    "allowInsecure": false
                },
                "tcpSettings": {
                    "type": "none"
                },
                "sockopt": {
                    "tproxy": "tproxy",
                    "mark": 255
                }
            }
        }
    ]
}
```