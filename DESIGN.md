# Tasarım Dokümanı — OWASP API Security Tests (Extended)

Bu doküman, 11 kaynak PDF'te (Injection, Kimlik Doğrulama/Oturum, İstemci Tarafı
Manipülasyon, Yetkilendirme/Erişim Kontrolü, İş Mantığı, SSRF/Dosya/Kaynak Tüketimi,
Güvenlik Yanlış Yapılandırması/Envanter, CWE↔OWASP eşleme tabloları, ThreatStats
karşılaştırmaları) kataloglanan test case'lerin **gerçek sink'lerle** nasıl
uygulanacağını eşler. Orijinal `Owasp-Api-Security-Tests-Playwright` reposunun
aksine burada:

- **Gerçek SQLite veritabanı** (`better-sqlite3`) — SQLi/NoSQLi-benzeri test edilebilir
- **Gerçek dosya yükleme + özel XML entity resolver** — XXE/billion-laughs/zip-bomb gerçekten tetiklenebilir
- **Gerçek GraphQL sunucusu** (`graphql-http`) — introspection/batching/BOLA testleri
- **Cookie tabanlı oturum** (`express-session`) — CSRF, session fixation, session hijacking anlamlı hale gelir
- **Basit OAuth2 authorization-code akışı** — redirect_uri/state/scope testleri
- **Gerçek komut çalıştırma** (zararsız komutlarla, `child_process`) — OS command injection
- **Gerçek zip-bomb** (`jszip`) — kaynak tüketimi/DoS testi

Her özellik için **secure** (`api-server/server.js`) ve **vulnerable**
(`api-server/server-vulnerable.js`) sürümleri paralel olarak uygulanır; aynı
test dosyası iki configle (`playwright.config.ts` / `playwright.config.vulnerable.ts`)
çalıştırıldığında secure'da PASS, vulnerable'da FAIL beklenir.

---

## 1. Veri Modeli (api-server/db/schema.sql mantığı, better-sqlite3)

| Tablo | Alanlar | Kullanım |
|---|---|---|
| `users` | id, email, password_hash, role, credits, verified, referral_code, security_question, security_answer | Auth, BOLA, BOPLA, business logic |
| `products` | id, name, description, stock, price | SQLi arama, race condition, mass purchase |
| `orders` | id, user_id, product_id, quantity, status, created_at | BOLA, race condition, negative qty |
| `comments` | id, product_id, user_id, body_html | Stored XSS |
| `referrals` | code, owner_id, used_by | Self-referral, çifte kullanım |
| `webhooks` | id, user_id, url | SSRF |
| `files` | id, owner_id, filename, path | Path traversal, dosya yükleme |
| `oauth_clients` | client_id, client_secret, redirect_uris, scopes | OAuth testleri |
| `oauth_codes` | code, client_id, user_id, redirect_uri, scope, expires_at | OAuth authorization-code akışı |
| `sms_budget` | id, counter, limit_cents | "Denial of Wallet" simülasyonu |

`server.js` ve `server-vulnerable.js` **aynı şemayı** kullanır; fark sorgu/kontrol
katmanındadır (parametrik vs string-concat, yetki kontrolü var/yok, vb.).

---

## 2. Endpoint Envanteri ve Aile Eşlemesi

### 2.1 Injection ailesi → `tests/injection.security.spec.ts`

| Endpoint | Sink | CWE | Secure davranış | Vulnerable davranış | PDF Test ID |
|---|---|---|---|---|---|
| `GET /api/products/search?q=` | SQL sorgusu | CWE-89 | Parametrik `?` sorgu | String concat `WHERE name LIKE '%${q}%'` | TC-I01–I03 |
| `POST /api/auth/login` (NoSQL-mod) | JS obje filtresi üzerinde operatör değerlendirme | CWE-943 | Yalnızca string eşitliği | `$ne`/`$gt` gibi anahtarları objeye aynen uygulama | TC-I04 |
| `POST /api/system/ping` | `child_process` | CWE-78/77 | `execFile('ping',['-c','1', allowlisted_host])` | `exec('ping -c 1 ' + host)` | TC-I05 |
| `POST /api/templates/render` | Basit `{{expr}}` değerlendirici | CWE-94 | Yalnızca whitelist değişken | `new Function('return ' + expr)()` | TC-I11 |
| `PUT/PATCH /api/users/me` | Obje birleştirme | CWE-1321 | Allow-list alan ataması | `Object.assign(user, req.body)` (prototip kirlenmesine açık) | TC-I21/I22 |
| `POST /api/comments` + `GET /api/products/:id/comments` | HTML render | CWE-79 | Encode/sanitize | Ham HTML saklama | TC-I17/I18 |
| `GET /api/search?tag=&tag=` | HPP | CWE-235 | İlk değeri al, dizi değilse reddet | Son değeri sessizce kullan | TC-I16 |
| `GET /api/auth/callback?redirect=` | Open redirect (host allow-list) | CWE-601 | Yalnızca izinli host | Doğrulamasız redirect | TC-UNSAFE-03 (orijinal) |

> SSI/LDAP/XML-injection (XPath)/IMAP-SMTP/Format-String/HTTP Response
> Splitting/Request Smuggling: bu protokol sink'leri (dizin servisi, mail
> sunucusu, native printf) modern bir Express/JSON API'sinde gerçekçi biçimde
> kurulamaz; XML sink'i **XXE ailesinde** (bkz. §2.5) gerçek olarak
> uygulanıyor, HTTP Response Splitting/Smuggling Node'un HTTP sunucusu
> tarafından zaten engellendiği için (header enjeksiyonu otomatik reddedilir)
> test edilemez — bu, raporların da kabul ettiği bir sınırdır.

### 2.2 Kimlik Doğrulama/Oturum ailesi → `tests/auth-session.security.spec.ts`

| Endpoint | CWE | Secure | Vulnerable | PDF Test ID |
|---|---|---|---|---|
| `POST /api/auth/login` | 307 | 5 başarısız denemede kilitleme | Kilitleme yok | TC-S03/S04 (orijinal AUTH-04) |
| `POST /api/auth/login` (JWT) | 347 | `alg:['HS256']` zorunlu, `exp/aud/iss` doğrulanır | `jwt.decode()` (doğrulamasız) | TC-S20/S21 (orijinal AUTH-05) |
| `POST /api/session/login` (cookie) | 384 | Login sonrası `req.session.regenerate()` | Aynı session ID korunur | TC-S14 Session Fixation |
| `POST /api/session/logout` | 613 | Sunucu tarafı session yok edilir | Yalnızca cookie silinir, sunucu session hâlâ geçerli | TC-S17 |
| `PUT /api/users/me/email` | 620 | Mevcut parola zorunlu | Parola istenmeden değişir | TC-S10 (API2 Senaryo #2) |
| `POST /api/users/me/security-question` | 640 | Rastgele/özel cevap | Tahmin edilebilir ("favori renk") | TC-S09 |
| Session çerezi | 1275/614 | `HttpOnly; Secure; SameSite=Strict` | Bayraklar eksik | TC-S13 |
| `POST /api/session/csrf-protected/change-email` | 352 | CSRF token kontrolü | Kontrol yok | TC-S16 (TC-C16) |

### 2.3 Yetkilendirme ailesi → `tests/authorization.security.spec.ts`

| Endpoint | CWE | Secure | Vulnerable | PDF Test ID |
|---|---|---|---|---|
| `GET /api/files/:name` | 22 | `path.join` + base dizin dışına çıkışı reddet | Doğrudan `fs.readFile(base+name)` | TC-A12 |
| `GET/PUT/DELETE /api/users/:id` | 639/862 | Sahiplik kontrolü | Kontrol yok | (orijinal BOLA testleri, aynen taşınır) |
| `POST /graphql` (`user(id)` query) | 285/639 | Resolver'da sahiplik kontrolü | Kontrol yok | TC-A03 (API BOLA) |
| `POST /graphql` introspection | 285 | `NoSchemaIntrospectionCustomRule` | Açık introspection | TC-A10 |
| `GET /oauth/authorize?redirect_uri=` | 601 | `redirect_uris` allow-list ile tam eşleşme | Herhangi bir `redirect_uri` kabul | TC-A16 |
| `POST /oauth/token` | 285 | `scope` istemci kaydına göre kısıtlı | İstemci istediği `scope`'u alır | TC-A17 |

### 2.4 İş Mantığı ailesi → `tests/business-logic.security.spec.ts`

| Endpoint | CWE | Secure | Vulnerable | PDF Test ID |
|---|---|---|---|---|
| `POST /api/orders` (eşzamanlı) | 362 | SQLite `BEGIN IMMEDIATE` transaction + stok kontrolü atomik | Oku-değiştir-yaz arasında kilit yok | TC-B17 (orijinal FLOW-01, güçlendirilmiş) |
| `POST /api/referrals/apply` (paralel) | 362 | `UNIQUE(code, used_by)` + transaction | Çifte kullanım mümkün | TC-B16 |
| `POST /graphql` batch mutation | 799 | Tek istekte mutation sayısı sınırlı | Sınırsız batch | TC-A11/B15 |
| Çok adımlı `POST /api/checkout/{start,confirm,pay}` | 841 | Sunucu tarafı adım durumu (state machine) | Adım atlanabilir | TC-B06 |

### 2.5 SSRF / Dosya / Kaynak Tüketimi ailesi → `tests/ssrf-resource.security.spec.ts`

| Endpoint | CWE | Secure | Vulnerable | PDF Test ID |
|---|---|---|---|---|
| `POST /api/webhooks` | 918 | `isInternalUrl` + redirect takip edilmez | Kontrol yok / redirect takip edilir | TC-S01/S02/S13 (orijinal SSRF) |
| `POST /api/files/upload` (`.xml`) | 611 | Özel parser'da entity resolution **kapalı** | Özel parser `SYSTEM` entity'i yerel dosyadan okur | TC-S04 |
| `POST /api/files/upload` (`.xml`, nested entity) | 776 | Entity genişleme derinliği sınırlı (max 3) | Sınırsız → CPU/süre patlaması | TC-S06 |
| `POST /api/files/upload` (`.zip`) | 409 | Açılmış boyut üst sınırı (`jszip` ile kontrollü extract) | Sınır yok | TC-S07 |
| `GET /api/products?limit=` | 770 | `Math.min(limit,100)` | Sınırsız | (orijinal CONS-02) |
| `POST /api/notifications/sms` | 770/400 | Kullanıcı başına/dakika sayaç | Sınırsız → `sms_budget` sayacı hızla tükenir | TC-S09 (Denial of Wallet simülasyonu, gerçek SMS gönderilmez) |

### 2.6 Güvenlik Yanlış Yapılandırması/Envanter ailesi → `tests/misconfig-inventory.security.spec.ts`

Orijinal repodaki testlerin (header, stack trace, debug endpoint, CORS, v1
deprecated, internal routes) birebir taşınması + ek: `/api/.env`, `/api/backup.sql`,
`/robots.txt`, `OPTIONS` ile metot keşfi, `TRACE`/`CONNECT` reddi, `/graphql`
introspection'ın misconfig açısından da işaretlenmesi.

### 2.7 İstemci Tarafı (Client-side/DevTools) ailesi → `tests/client-side.security.spec.ts` (gerçek tarayıcı, `chromium` projesi)

`public/` altında sunulan statik sayfalar:

| Sayfa | Amaç | CWE | PDF Test ID |
|---|---|---|---|
| `public/profile.html` | URL hash'i DOM'a `innerHTML` ile yazar (vulnerable) / `textContent` (secure) | 79 | TC-C01 DOM XSS |
| `public/redirect.html?to=` | `location.href = to` (vulnerable) / allow-list (secure) | 601 | TC-C04 |
| `public/frame-target.html` | `X-Frame-Options` sunucudan gelir | 1021 | TC-C08 Clickjacking |
| `public/postmessage.html` | `window.addEventListener('message', e => eval(e.data))` (vulnerable) / origin kontrolü (secure) | 346 | TC-C10 |
| `public/storage.html` | `localStorage.setItem('role', ...)` sonra yetkiyi oradan okuma (vulnerable) / sunucudan doğrulama (secure) | 565 | TC-C11/C12 |
| `public/tabnabbing.html` | `target="_blank"` linki `rel="noopener"` ile/siz | 1022 | TC-C14 |

Bu sayfalar `server.js`/`server-vulnerable.js` tarafından statik olarak
sunulur; hangi sunucuya karşı çalıştırıldığına göre davranışları değişir.

---

## 3. Dışarıda bırakılanlar (gerekçeli)

| PDF maddesi | Neden dışarıda |
|---|---|
| LDAP/IMAP/SMTP/SSI Injection | Gerçek dizin servisi/mail sunucusu/SSI motoru kurmak projenin kapsamını orantısız büyütür; XXE ailesinde eşdeğer bir "güvenilmeyen harici kaynak çözümleme" sink'i gerçek olarak zaten var. |
| HTTP Request Smuggling / Response Splitting | Node'un `http` modülü CRLF enjeksiyonunu ve çelişkili CL/TE başlıklarını zaten düşük seviyede reddediyor; Playwright `APIRequestContext` da ham soket seviyesinde header enjeksiyonuna izin vermiyor. |
| Format String Injection | Native kod (C/C++) native printf ailesine özgü; Node.js'te anlamlı bir sink yok. |
| Bellek güvenliği ailesi (CWE-787/416/125/120-122/476) | Native kod zafiyeti; Node.js/V8 seviyesinde kara-kutu API testiyle kanıtlanamaz (fuzzing/ASan gerektirir). |

Bu dört madde dışında PDF'lerdeki **tüm aileler** gerçek bir sink'le bu
projede karşılığını bulur.
