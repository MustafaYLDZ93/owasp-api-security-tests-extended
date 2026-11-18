# OWASP API Security Top 10 — Genişletilmiş Playwright Test Süiti

[`Owasp-Api-Security-Tests-Playwright`](https://github.com/mustafayldz93/owasp-api-security-tests-playwright)
reposunun **genişletilmiş** sürümü. 11 kaynak PDF'te (Injection, Kimlik
Doğrulama/Oturum, İstemci Tarafı Manipülasyon, Yetkilendirme/Erişim Kontrolü,
İş Mantığı, SSRF/Dosya/Kaynak Tüketimi, Güvenlik Yanlış Yapılandırması/Envanter,
CWE↔OWASP eşleme tabloları, ThreatStats karşılaştırmaları) kataloglanan test
case'lerin **gerçek sink'lerle** (gerçek SQLite veritabanı, gerçek XML entity
resolver, gerçek GraphQL sunucusu, cookie tabanlı oturum, basit bir OAuth2
akışı, gerçek shell komut çalıştırma) karşılığını verir.

Proje iki modda çalışır:
- **Güvenli API** → Tüm testler PASS (savunmalar doğrulandı) — **79/79**
- **Açıklı API** → Testler FAIL (güvenlik açıkları tespit edildi) — **76 FAIL + 3 pozitif kontrol PASS**

Tüm tasarım kararları ve her endpoint'in hangi CWE/OWASP/PDF test ID'sine
karşılık geldiği [`DESIGN.md`](./DESIGN.md) dosyasında ayrıntılı olarak
belgelenmiştir.

---

## İçindekiler

- [Orijinal Projeden Farklar](#orijinal-projeden-farklar)
- [Proje Yapısı](#proje-yapısı)
- [Test Aileleri](#test-aileleri)
- [API Sunucuları](#api-sunucuları)
- [Kurulum](#kurulum)
- [Testleri Çalıştırma](#testleri-çalıştırma)
- [Test Sonuçları](#test-sonuçları)
- [GitHub Actions](#github-actions)
- [Kapsam Dışı Bırakılanlar](#kapsam-dışı-bırakılanlar)

---

## Orijinal Projeden Farklar

| | Orijinal repo | Bu proje |
|---|---|---|
| Veri katmanı | In-memory JS array | Gerçek SQLite (`better-sqlite3`) |
| XML işleme | Yok | Özel entity resolver — gerçek XXE/billion-laughs |
| GraphQL | Yok | Gerçek GraphQL sunucusu (introspection/batching/BOLA) |
| OAuth | Yok | Basit OAuth2 authorization-code akışı |
| Oturum | Yalnızca JWT (Bearer) | JWT **+** cookie tabanlı session (CSRF, fixation test edilebilir) |
| Dosya yükleme | Yok | Gerçek multipart upload (path traversal, XXE, zip-bomb) |
| Komut çalıştırma | Yok | Gerçek shell exec (`echo`/`sleep` tabanlı, zaman-tabanlı oracle) |
| İstemci tarafı testleri | Yok | Gerçek tarayıcı (`chromium` projesi) + 6 demo HTML sayfası |
| Test sayısı | 42 | **79** |

---

## Proje Yapısı

```
owasp-api-security-tests-extended/
│
├── DESIGN.md                          # Tam tasarım/eşleme dokümanı
├── tests/
│   ├── helpers.ts
│   ├── injection.security.spec.ts            # 14 test
│   ├── auth-session.security.spec.ts         # 11 test
│   ├── authorization.security.spec.ts        # 17 test
│   ├── business-logic.security.spec.ts       #  6 test
│   ├── ssrf-resource.security.spec.ts        # 12 test
│   ├── misconfig-inventory.security.spec.ts  # 13 test
│   └── client-side.security.spec.ts          #  6 test (gerçek tarayıcı)
│
├── playwright.config.ts               # Güvenli API konfigürasyonu
├── playwright.config.vulnerable.ts    # Açıklı API konfigürasyonu
├── global-setup.ts / global-teardown.ts
│
├── api-server/
│   ├── server.js                      # Güvenli API (port 3000)
│   ├── server-vulnerable.js           # Açıklı API (port 3001)
│   ├── db/init.js                     # SQLite şema + seed
│   ├── lib/                           # Paylaşılan sink modülleri
│   │   ├── hash.js, nosql-match.js, system-exec.js, template-engine.js
│   │   ├── xml-resolver.js            # Özel XXE/billion-laughs motoru
│   │   ├── ssrf-guard.js              # IP-gizleme bypass'ına dayanıklı SSRF kontrolü
│   │   ├── graphql-schema.js, oauth.js, rate-window.js
│   ├── fixtures/secret.txt            # XXE/path-traversal hedef dosyası
│   └── public-downloads/welcome.txt   # Path traversal pozitif kontrolü
│
├── public/
│   ├── secure/      # 6 demo HTML sayfası — güvenli davranış
│   └── vulnerable/  # Aynı 6 sayfa — açıklı davranış
│
└── .github/workflows/security-tests.yml
```

---

## Test Aileleri

### `injection.security.spec.ts` — 14 test
SQL Injection (parametrik vs string-concat, gerçek SQLite), NoSQL/operatör
enjeksiyonu, OS komut enjeksiyonu (gerçek shell, zaman tabanlı oracle), SSTI
(`new Function` vs whitelist), Mass Assignment/Prototype Pollution, HTTP
Parameter Pollution, Stored XSS.

### `auth-session.security.spec.ts` — 11 test
Brute-force kilitleme, güvenlik sorusu cevabı kilitleme, JWT `alg:none`/
`exp`/`aud` doğrulaması, hassas değişiklikte mevcut parola zorunluluğu,
session fixation (gerçek cookie takibi), session çerez bayrakları, logout
geçersiz kılma, CSRF koruması.

### `authorization.security.spec.ts` — 17 test
BOLA (GET/PUT/DELETE), BFLA, BOPLA/aşırı veri ifşası, path traversal, dosya
indirmede BOLA, GraphQL introspection/BOLA/batching, OAuth2 `redirect_uri`/
`scope` doğrulaması.

### `business-logic.security.spec.ts` — 6 test
Stok yarış durumu (gerçek eşzamanlı istekler, atomik transaction vs TOCTOU),
negatif miktar, self-referral, iş akışı adımı atlama, kupon çifte harcama
(race condition).

### `ssrf-resource.security.spec.ts` — 12 test
İç adres/bulut metadata engeli, **IP gizleme (decimal/hex) filtre atlatma**,
domain allowlist, open redirect, gerçek XXE (yerel dosya okuma), gerçek
billion-laughs, gerçek zip-bomb, sayfalama/payload sınırı, "Denial of Wallet"
simülasyonu.

### `misconfig-inventory.security.spec.ts` — 13 test
Güvenlik header'ları, CORS, stack trace sızıntısı, debug/swagger endpoint'leri,
Cache-Control, eski API sürümü, shadow endpoint'ler, GraphQL envanteri.

### `client-side.security.spec.ts` — 6 test (gerçek `chromium` tarayıcısı)
DOM XSS, istemci tarafı open redirect, clickjacking (gerçek iframe + 
`X-Frame-Options`), **çapraz-origin postMessage** (ayrı bir HTTP sunucusuyla
gerçek farklı origin simülasyonu), localStorage'a güvenerek yetki kararı,
reverse tabnabbing.

---

## API Sunucuları

### `server.js` — Güvenli API (Port 3000)
Tüm güvenlik kontrollerini uygular. Tüm testler **PASS** olur.

### `server-vulnerable.js` — Açıklı API (Port 3001)
Kasıtlı olarak güvensiz yazılmıştır; **DO NOT deploy**.

**Ön tanımlı kullanıcılar (her iki sunucu için aynı):**

| E-posta | Şifre | ID | Rol |
|---|---|---|---|
| user_a@test.com | Password123! | 10 | user |
| user_b@test.com | Password123! | 2 | user |
| admin@test.com | AdminPass123! | 3 | admin |

`POST /api/auth/register` ile testler kendi **atılabilir (disposable)**
kullanıcılarını oluşturabilir — bu sayede yıkıcı testler (hesap silme vb.)
sabit seed verisini bozmaz.

---

## Kurulum

**Gereksinimler:** Node.js 18+

```bash
npm install
npx playwright install chromium   # yalnızca client-side ailesi için gerekli
```

---

## Testleri Çalıştırma

```bash
# Güvenli API — tüm testler PASS
npx playwright test

# Açıklı API — güvenlik açıkları tespit edilir (FAIL beklenir)
npx playwright test --config=playwright.config.vulnerable.ts

# Yalnızca API (tarayıcısız) testler
npx playwright test --project=api

# Yalnızca client-side (tarayıcı) testleri
npx playwright test --project=chromium

# Belirli bir aile
npx playwright test injection.security.spec.ts

# HTML rapor
npx playwright show-report
```

> `globalSetup` sayesinde testler çalıştırıldığında ilgili API sunucusu
> otomatik başlar ve biter; manuel başlatmaya gerek yoktur
> (`npm run start:api` / `npm run start:api:vulnerable` manuel çalıştırma
> içindir).

---

## Test Sonuçları

| Mod | Toplam | PASS | FAIL |
|---|---|---|---|
| Güvenli API | 79 | 79 | 0 |
| Açıklı API | 79 | 3 (pozitif kontrol) | 76 |

> **Not — yarış durumu testleri:** `promo-item-001` stok tükenmesi ve
> `WELCOME10` kupon çifte harcama testleri gerçek eşzamanlılık kullanır;
> açıklı sunucudaki yapay gecikme penceresi (25ms) bu testlerin yoğun
> sistem yükü altında da güvenilir biçimde tetiklenmesi için genişletilmiştir.

---

## GitHub Actions

Repo → **Actions** → **OWASP API Security Tests (Extended)** → **Run workflow**

| Seçenek | Beklenen Sonuç |
|---|---|
| `secure` | 79/79 PASS |
| `vulnerable` | 76 FAIL + 3 PASS (pozitif kontroller) |
| `both` | Her ikisi sırayla |

---

## Kapsam Dışı Bırakılanlar

LDAP/IMAP/SMTP/SSI Injection, HTTP Request Smuggling/Response Splitting,
Format String Injection ve native bellek güvenliği ailesi (CWE-787/416/125/
120-122/476) bu projede **gerçekçi bir sink'e sahip olmadığı** için kasıtlı
olarak dışarıda bırakılmıştır — gerekçe ve ayrıntı için bkz.
[`DESIGN.md` §3](./DESIGN.md#3-dışarıda-bırakılanlar-gerekçeli).
