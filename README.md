# vk-turn-proxy
Проброс трафика WireGuard через TURN сервера VK звонков. Пакеты шифруются DTLS 1.2, затем параллельными потоками через TCP или UDP отправляются на TURN сервер по протоколу STUN ChannelData. Оттуда по UDP отправляются на ваш сервер, где расшифровываются и передаются в WireGuard. Логин/пароль от TURN генерируются из ссылки на звонок.

Только для учебных целей!
## Настройка
Нам понадобится:
1. Ссылка на действующий ВК звонок: создаём свой (нужен аккаунт вк), или гуглим `"https://vk.com/call/join/"`.
Ссылка действительна вечно, если не нажимать "завершить звонок для всех"
2. VPS с установленным WireGuard
3. Для андроида: скачать Termux из F-Droid
### Сервер
`./server -listen 0.0.0.0:56000 -connect 127.0.0.1:<порт wg>`
### Клиент
#### Android
1. В клиентском конфиге WireGuard меняем адрес сервера на `127.0.0.1:9000`, ставим MTU 1280
2. **Добавляем Termux в исключения WireGuard. Нажимаем "сохранить".**

В Termux:

3. `termux-wake-lock` Телефон не будет уходить в глубокий сон, так что на ночь ставьте на зарядку. Чтобы отключить: `termux-wake-unlock`
4. Копируем бинарник в локальную папку, даём права на исполнение:
5. `cp /sdcard/Download/client-android ./`
6. `chmod 777 ./client-android`
7. `./client-android -peer <ip сервера wg>:56000 -link <VK ссылка> -listen 127.0.0.1:9000`

**Если после включения VPN в терминале вылезают ошибки DNS, попробуйте в Wireguard включить VPN только для нужных приложений.**
#### Linux
В клиентском конфиге WireGuard меняем адрес сервера на `127.0.0.1:9000`, ставим MTU 1280

Скрипт будет добавлять маршруты к нужным ip:

`./client-linux -peer <ip сервера wg>:56000 -link <VK ссылка> -listen 127.0.0.1:9000 | sudo routes.sh`

Не включайте впн, пока программа не установит соединение! В отличие от андроида, здесь часть запросов будет идти через впн (dns и запрос подключения к turn)
#### Windows
В клиентском конфиге WireGuard меняем адрес сервера на `127.0.0.1:9000`, ставим MTU 1280

В PowerShell от Администратора (чтобы скрипт прописывал маршруты):

`./client.exe -peer <ip сервера wg>:56000 -link <VK ссылка> -listen 127.0.0.1:9000 | routes.ps1`

Не включайте впн, пока программа не установит соединение! В отличие от андроида, здесь часть запросов будет идти через впн (dns и запрос подключения к turn)
### Если не работает
С помощью опции `-turn` можно указать адрес TURN сервера вручную. Это должен быть сервер ВК, Макса или Одноклассников. Возможно потом составлю список.

Если не работает TCP, попробуйте добавить флаг `-udp`.

Добавьте флаг `-n 1` для более стабильного подключения в 1 поток (ограничение 5 Мбит/с)

## v2ray

Вместо WireGuard можно использовать любое V2Ray-ядро которое его поддерживает (например, xray или sing-box) и любой V2Ray-клиент который использует это ядро (например, v2rayN или v2rayNG). С помощью их вы сможете добавить больше входящих интерфейсов (например, SOCKS) и реализовать точечный роутинг.

Пример конфигов:

<details>

<summary>
Клиент
</summary>

```json
{
    "inbounds": [
        {
            "protocol": "socks",
            "listen": "127.0.0.1",
            "port": 1080,
            "settings": {
                "udp": true
            },
            "sniffing": {
                "enabled": true,
                "destOverride": [
                    "http",
                    "tls"
                ]
            }
        },
        {
            "protocol": "http",
            "listen": "127.0.0.1",
            "port": 8080,
            "sniffing": {
                "enabled": true,
                "destOverride": [
                    "http",
                    "tls"
                ]
            }
        }
    ],
    "outbounds": [
        {
            "protocol": "wireguard",
            "settings": {
                "secretKey": "<client secret key>",
                "peers": [
                    {
                        "endpoint": "127.0.0.1:9000",
                        "publicKey": "<server public key>"
                    }
                ],
                "domainStrategy": "ForceIPv4",
                "mtu": 1280
            }
        }
    ]
}
```

</details>

<details>

<summary>
Сервер
</summary>

```json
{
    "inbounds": [
        {
            "protocol": "wireguard",
            "listen": "0.0.0.0",
            "port": 51820,
            "settings": {
                "secretKey": "<server secret key>",
                "peers": [
                    {
                        "publicKey": "<client public key>"
                    }
                ],
                "mtu": 1280
            },
            "sniffing": {
                "enabled": true,
                "destOverride": [
                    "http",
                    "tls"
                ]
            }
        }
    ],
    "outbounds": [
        {
            "protocol": "freedom",
            "settings": {
                "domainStrategy": "UseIPv4"
            }
        }
    ]
}
```

</details>