# TUNNEL-MANAGER-CORE

هستهٔ دیتاپلینِ رمزنگاری‌شده — یک باینریِ Go استاتیک و بدونِ وابستگی. پنلِ مرکزی و
نودِ Python ارکستریت می‌کنند؛ این هسته فقط بسته‌ها را جابه‌جا می‌کند و ورودی/خروجیِ
تعاملی ندارد.

> در استقرارِ واقعی هسته را **دستی نمی‌سازی**: پنل نسخهٔ ریلیز را دانلود و به نودها
> push می‌کند. مراحلِ زیر فقط برای توسعه/ساختِ دستی است.

## پیش‌نیاز

| ابزار | نسخه | برای چه |
|---|---|---|
| `go` | 1.25+ | ساختِ باینری (فقط دستی) |
| `git` | — | دریافتِ کد |
| Linux | kernel با TUN | اجرا |

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

## ترنسپورت‌ها

| `transport` | کاربرد |
|---|---|
| `udp` | پیش‌فرض، سبک |
| `tcp` | استریمی، پایدار پشتِ فایروال |
| `raw` | proto خام — `bip` (253 نیتیو) / `ipip` / `gre` / `icmp` / `udp` / `tcp` |
| `flux` | چندریختیِ چرخشی (حامل‌های udp/stun/raw، چرخشِ ساعتی) |
| `ws` | WebSocket/xHTTP روی CDN (دامنه‌فرونتینگ) |

## قابلیت‌ها

| کلید | کار |
|---|---|
| `crypto` | AES-256-GCM با دست‌دادِ X25519 برای هر نشست (forward secrecy) |
| `obfs` | حذفِ بایتِ ثابت + padding + jitter (ضدِ DPI) |
| `cover` | پوششِ TLS به‌سبکِ REALITY (فقط tcp) |
| `fec` | تصحیحِ خطای Reed-Solomon روی خطِ پرتلفات (udp/raw/flux) |
| `spoof_src_ip` / `spoof_dst_ip` | جعلِ IP مبدأ/مقصد (روی پروفایلِ raw `bip`) |

## فرمتِ سیم

با `obfs` روشن، هیچ فیلدِ ثابتی روی سیم نیست: کل فریم ciphertextِ AEAD به‌علاوهٔ
padding است و طولِ واقعی داخلِ فریمِ sealed قرار دارد. فرمتِ legacy (obfs خاموش):

```
[0] magic = 0xB1
[1] type  = 0 data | 1 ping | 2 pong
[2:] payload   (رمز روشن: sealed؛ خاموش: بستهٔ خامِ IP)
```

---

ارکستریت با 👉 [tnl-central](https://github.com/Angize/TUNNEL-MANAGER) + [tnl-node](https://github.com/Angize/TUNNEL-MANAGER-NODE) • مجوز 👉 [LICENSE](./LICENSE)
