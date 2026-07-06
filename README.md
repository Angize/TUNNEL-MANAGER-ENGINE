# TUNNEL-MANAGER-CORE

هستهٔ دیتاپلینِ اختصاصی برای پنلِ مدیریتِ ناوگانِ تونل — یک باینریِ Go (static، بدونِ
وابستگی). پنلِ مرکزی و نودِ agent (Python) همچنان ارکستریتور می‌مانند؛ این هسته فقط
دادهٔ خام را جابه‌جا می‌کند.

Custom data-plane core for the tunnel fleet manager. A single static Go
binary with no external dependencies. The Python panel and node agent stay the
orchestrators; this core only moves packets.

## وضعیت (این نسخه)

پیاده‌سازیِ برشِ اول — **حالتِ Packet با پروفایلِ `bip`**:

- یک اینترفیسِ **TUN** روی هر نود (بستهٔ خامِ L3).
- حاملِ **bip**: هر بستهٔ IP در یک datagramِ **UDP** بسته‌بندی می‌شود.
- رمزنگاریِ اختیاری **AES-256-GCM** (کلید از PSK با SHA-256، nonceِ تصادفی برای هر بسته).
- نقش‌ها: `server` (عمومی، listen) و `client` (پشتِ NAT، dial + keepalive) — سازگار با NAT.

بقیهٔ ترنسپورت‌ها (tcp/tcpmux/ws/wss/mux/anytls/…) و پروفایل‌های packet
(icmp/ipip/udp/tcp/gre) لایه‌لایه بعد از این اضافه می‌شوند.

## ساخت

```sh
CGO_ENABLED=0 go build -o tnl-core .
```

## اجرا

روی نودِ عمومی (server):

```sh
sudo ./tnl-core --config examples/server.json
```

روی نودِ پشتِ NAT (client) — فیلدِ `peer` را به آی‌پیِ عمومیِ server بگذار:

```sh
sudo ./tnl-core --config examples/client.json
```

سپس ترافیکِ `10.200.0.0/24` از تونل عبور می‌کند (مثلاً `ping 10.200.0.2`).

## قراردادِ کنترل

هسته stdin/stdout تعاملی ندارد؛ نود یک فایلِ `core-<id>.json` می‌نویسد و باینری را با
`--config <path>` اجرا می‌کند — دقیقاً مثلِ اینکه نود الان `ip`/`iptables` را صدا می‌زند.

## فرمتِ سیم (bip)

هر datagramِ UDP یک فریم است:

```
[0] magic = 0xB1
[1] type  = 0 data | 1 ping | 2 pong
[2:] payload   (data: در صورتِ روشن‌بودنِ رمز، nonce||ciphertext؛ وگرنه بستهٔ خامِ IP)
```

## تست

```sh
go test ./...
```

تستِ end-to-end (دو namespace، ping + انتقالِ TCP روی تونلِ رمزشده) در تاریخچهٔ توسعه
اجرا و تأیید شده است.

## امنیت

`psk` هرگز به مرورگر یا خروجیِ عمومیِ نود بازتاب داده نمی‌شود.
