# TUNNEL-MANAGER-CORE

هستهٔ دیتاپلینِ رمزنگاری‌شده — یک باینریِ Go استاتیک و بدونِ وابستگی. پنلِ مرکزی و
نودِ Python ارکستریت می‌کنند؛ این هسته فقط بسته‌های L3 را بینِ یک دستگاهِ TUN و یک
همتای نقطه‌به‌نقطه جابه‌جا می‌کند و ورودی/خروجیِ تعاملی ندارد. ترنسپورت، رمز، ضدِDPI،
جعلِ IP و چرخشِ هدفِ متحرک همه از روی یک فایلِ config انتخاب می‌شوند.

> در استقرارِ واقعی هسته را **دستی نمی‌سازی**: پنل نسخهٔ ریلیز را دانلود و به نودها
> push می‌کند. مراحلِ زیر فقط برای توسعه/ساختِ دستی است.

## پیش‌نیاز

| ابزار | نسخه | برای چه |
|---|---|---|
| `go` | 1.25+ | ساختِ باینری (فقط دستی) |
| `git` | — | دریافتِ کد |
| Linux | kernel با TUN | اجرا |

راه‌های ضدِسانسورِ خام (`raw`/`flux`/جعلِ IP/بعضی حالت‌های `fake_desync`) به
`CAP_NET_RAW` نیاز دارند و فقط روی Linux کار می‌کنند.

## راه‌اندازی از صفر

```sh
# ۱) پیش‌نیازها (Debian/Ubuntu) — یا Go رسمیِ 1.25+
sudo apt update && sudo apt install -y golang git

# ۲) کلون
git clone https://github.com/Angize/TUNNEL-MANAGER-CORE.git
cd TUNNEL-MANAGER-CORE

# ۳) ساخت (استاتیک، بدونِ CGO)
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go build -trimpath -ldflags "-s -w" -o tnl-core .

# ۴) تست
go test ./...

# ۵) اجرا (معمولاً نود این کار را می‌کند)
sudo ./tnl-core --config core-<id>.json
```

نود فایلِ `core-<id>.json` را می‌نویسد و باینری را با `--config <path>` اجرا می‌کند.

| فلگ | کار |
|---|---|
| `--config <path>` | مسیرِ فایلِ JSONِ پیکربندی (تنها راهِ اجرای واقعی) |
| `--version` | چاپِ نسخه و خروج |
| `--probe-spoof` | چاپِ توانِ جعلِ IP به‌صورت JSON و خروج (نود برای `spoof-probe` صدا می‌زند) |

## ترنسپورت‌ها

| `transport` | کاربرد |
|---|---|
| `udp` | پیش‌فرض، سبک، سازگار با NAT |
| `tcp` | استریمی، پایدار پشتِ فایروال؛ تنها ترنسپورتی که `cover` (پوششِ TLS) می‌پذیرد |
| `raw` | بستهٔ خامِ IP — پروفایل `bip` (253 نیتیو) / `ipip` / `gre` / `icmp` / `udp` / `tcp` / `esp` (50)؛ پشتیبانِ جعلِ IP |
| `flux` | چندریختیِ چرخشی — حاملِ `udp`/`stun`/`raw`؛ شکل (پروتکل/پورت/padding) هر epoch از `HKDF(PSK, ساعت)` عوض می‌شود، **بدونِ هیچ سیگنالِ روی سیم** |
| `ws` | WebSocket یا xHTTP روی CDN (دامنه‌فرونتینگ) — با ECH، poolِ چرخشیِ edge و warm-standby |
| `dns` | تونلِ DNS — نشستِ AEAD/KCP داخلِ کوئری‌های DNS؛ راهِ آخر زیرِ وایت‌لیستِ کاملِ پروتکل+مقصد |

## قابلیت‌ها

| کلید | کار |
|---|---|
| `crypto` | AEAD (`aes-256-gcm` پیش‌فرض، `aes-128-gcm`, `chacha20-poly1305`, `xchacha20-poly1305`؛ `auto`→aes-256-gcm) با **دست‌دادِ زودگذرِ X25519 برای هر نشست** (forward secrecy) + احرازِ PSK + ضدِبازپخش (anti-replay) |
| `obfs` | حذفِ بایتِ ثابت + padding + jitter + ماسکِ طولِ TCP (ضدِ DPI)؛ به `crypto` نیاز دارد |
| `cover` | پوششِ TLS به‌سبکِ REALITY (اثرِانگشتِ Chrome، فقط `tcp`) — پروبِ ناشناس را شفاف به `cover_sni:443`ِ واقعی پراکسی می‌کند |
| `fec` | تصحیحِ خطای Reed-Solomon روی خطِ پرتلفات (`udp`/`raw`/`flux`) |
| `spoof_src_ip` / `spoof_dst_ip` | جعلِ IPِ مبدأ / مقصدِ طعمه (روی پروفایلِ `raw` `bip`) |
| ECH | رمزکردنِ SNIِ واقعی داخلِ ClientHello (`ws` + `wss`)؛ نود کلید را از رکوردِ HTTPSِ دامنه روی DoH می‌گیرد |
| poolِ edge | چرخشِ ترکیبِ (IPِ edge × SNI) با auto-burn و warm-standby (make-before-break) برای `ws` |
| `xhttp` | GET-پایین/POST-بالا (`packet`) یا استریمِ دوطرفهٔ gRPC — عبور از CDNهایی که WebSocket را می‌بندند |
| SNI-split | تکه‌کردنِ ClientHelloِ wss (`split`/`disorder`/`fake`) برای شکستِ DPIِ مبتنی بر SNI |
| `fake_desync` | بسته‌های طعمه پیش از هر دست‌داد برای بی‌سنکرون‌کردنِ DPIِ حالت‌مند (`raw`/`flux`/`tcp`/`ws`) |
| poolِ چرخشی | چرخشِ IPِ مقصد و مبدأ برای ترنسپورت‌های مستقیم (`udp`/`tcp`/`raw`/`flux`) با burnِ IPِ بلاک‌شده |
| `tuning` | تنظیمِ عملیاتیِ تایمینگِ سلامت/تشخیصِ مرگ/چرخش توسطِ اپراتور |
| `gso` | سگمنت‌آفلودِ TUN برای گذردهیِ بالاتر (بهینه‌سازیِ محلی، فرمتِ سیم بی‌تغییر) |

## فرمتِ سیم

با `obfs` روشن، هیچ فیلدِ ثابتی روی سیم نیست: کل فریم ciphertextِ AEAD به‌علاوهٔ
padding است و طولِ واقعی داخلِ فریمِ sealed قرار دارد. با `crypto` روشن ولی `obfs`
خاموش (فرمتِ legacy):

```
[0] magic = 0xB1
[1] type  = 0 data | 1 ping | 2 pong
[2:] payload   (رمز روشن: sealed؛ خاموش: بستهٔ خامِ IP)
```

> ⚠️ با `crypto` خاموش هیچ احراز و ضدِبازپخشی نیست؛ هرکس بتواند بسته‌ای به listener
> بفرستد می‌تواند تونل را برباید یا به آن تزریق کند. جز روی لینکِ مطمئن و ایزوله،
> `crypto` را روشن نگه دار.

---

ارکستریت با 👉 [tnl-central](https://github.com/Angize/TUNNEL-MANAGER) + [tnl-node](https://github.com/Angize/TUNNEL-MANAGER-NODE) • مجوز 👉 [LICENSE](./LICENSE)
