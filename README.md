# TUNNEL-MANAGER-CORE

هستهٔ دیتاپلینِ اختصاصی برای پنلِ مدیریتِ ناوگانِ تونل — یک باینریِ Go (static، بدونِ
وابستگی). پنلِ مرکزی و نودِ agent (Python) همچنان ارکستریتور می‌مانند؛ این هسته فقط
دادهٔ خام را جابه‌جا می‌کند.

Custom data-plane core for the tunnel fleet manager. A single static Go
binary with no external dependencies. The Python panel and node agent stay the
orchestrators; this core only moves packets.

## وضعیت (این نسخه)

**حالتِ Packet با پروفایلِ `core`**:

- یک اینترفیسِ **TUN** روی هر نود (بستهٔ خامِ L3).
- چند **ترنسپورت** برای حملِ فریم‌ها: `udp` (پیش‌فرض)، `tcp`، `raw` (پروفایل‌های
  raw: `bip`=proto-253 نیتیو / `ipip` / `gre` / `icmp` / `udp` / `tcp`)، `flux`
  (حاملِ چندریختیِ چرخشی: udp/stun/raw) و `ws` (WebSocket/xHTTP روی CDN).
- رمزنگاریِ **AES-256-GCM** با دست‌دادِ X25519 برای هر نشست (forward secrecy).
- ضدِ DPIِ اختیاری (`obfs`): حذفِ بایت‌های ثابت + padding + jitter؛ پوششِ TLS به‌سبکِ
  REALITY (`cover`)؛ تصحیحِ خطا (`fec`)؛ جعلِ IP مبدأ/مقصد روی پروفایلِ raw `bip`.
- نقش‌ها: `server` (عمومی، listen) و `client` (پشتِ NAT، dial + keepalive) — سازگار با NAT.

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

## فرمتِ سیم

هر datagramِ UDP (یا فریمِ استریمی روی tcp/ws) یک فریم است. فرمتِ legacy:

```
[0] magic = 0xB1              (فقط در framingِ legacy؛ با obfs هیچ بایتِ ثابتی نیست)
[1] type  = 0 data | 1 ping | 2 pong
[2:] payload   (data: در صورتِ روشن‌بودنِ رمز، sealed؛ وگرنه بستهٔ خامِ IP)
```

با روشن‌بودنِ `obfs` هیچ فیلدِ ثابتی روی سیم نیست: کلِ فریم ciphertextِ AEAD به‌علاوهٔ
padding است و طولِ واقعی داخلِ فریمِ sealed قرار دارد.

## تست

```sh
go test ./...
```

تستِ end-to-end (دو namespace، ping + انتقالِ TCP روی تونلِ رمزشده) در تاریخچهٔ توسعه
اجرا و تأیید شده است.

## امنیت

`psk` هرگز به مرورگر یا خروجیِ عمومیِ نود بازتاب داده نمی‌شود.
