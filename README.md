# Guruh boshqaruvi sayti

Topshiriqlar, kunlik yo'qlama va ishtirok statistikasi uchun Flask ilovasi.

## Mahalliy ishga tushirish

```
pip install -r requirements.txt
HTTPS=0 python app.py
```

`http://localhost:5000` manziliga kiring. Birinchi kirish: login `admin`, parol `admin123`.
Darhol **Parol** bo'limidan o'zgartiring.

## Muhit o'zgaruvchilari

| Nomi | Vazifasi | Tavsiya |
|---|---|---|
| `SECRET_KEY` | Sessiyalarni imzolash | Uzun tasodifiy qator (majburiy serverda) |
| `ADMIN_USER` / `ADMIN_PASS` | Birinchi admin (faqat bo'sh bazada) | Serverda o'rnating |
| `DB_PATH` | SQLite fayl yo'li | Doimiy disk ichida |
| `UPLOAD_DIR` | Yuklangan fayllar papkasi | Doimiy disk ichida (masalan `/data/uploads`) |
| `HTTPS` | `1` bo'lsa cookie faqat HTTPS orqali | Serverda `1` (standart) |
| `FLASK_DEBUG` | Debug rejim | Serverda `0` (standart) |
| `PORT` | Port | Hosting o'zi beradi |

Tasodifiy SECRET_KEY yaratish:

```
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

## Render'ga joylash

1. Kodni GitHub repozitoriyasiga yuklang (`app.py`, `requirements.txt`).
2. Render'da **New Web Service** tanlang va repozitoriyani ulang.
3. Sozlamalar:
   - Build command: `pip install -r requirements.txt`
   - Start command: `gunicorn app:app`
   - Health check path: `/health`
4. **Disks** bo'limida doimiy disk qo'shing (masalan, `/data`, 5 GB) va `DB_PATH=/data/guruh.db`, `UPLOAD_DIR=/data/uploads` qo'ying.
   Diskisiz SQLite ma'lumotlari server qayta ishga tushganda yo'qolishi mumkin.
5. Environment bo'limida `SECRET_KEY`, `ADMIN_PASS` ni kiriting.
6. Deploy qiling, so'ng birinchi navbatda admin parolini o'zgartiring.

## Testlar

Testlar `tests/` papkasida. Oddiy testlar (serversiz):

```
python tests/test_asosiy.py
python tests/test_chat.py
python tests/test_yuklash.py
```

Brauzer testlari (server ishlab turgan bo'lishi kerak, `playwright` kerak):

```
python tests/brauzer_oqimlari.py
python tests/ekran_tekshiruvi.py
```

Test skriptlari ichidagi manzil va baza yo'llarini o'zingizga moslang.

## Ma'lum cheklovlar

- Yuklanadigan fayllar: JPG, PNG, GIF, WEBP, PDF, har biri 10 MB gacha. Fayllar diskda saqlanadi, ular uchun ham doimiy disk kerak.
- Topshiriq javobiga fayl yuklash yo'q (faqat matn va havola).
- Bir vaqtning o'zida juda ko'p foydalanuvchi uchun SQLite emas, PostgreSQL tavsiya etiladi.
- Login cheklovi xotirada saqlanadi, server qayta ishga tushsa tiklanadi.
- Ishlash uchun brauzerda JavaScript yoqilgan bo'lishi kerak (CSRF himoyasi va chat shunga bog'liq).
- Sayt telefon (390 px) va noutbuk (1366 px) ekranlarida tekshirilgan. Keng jadvallar telefonda gorizontal aylantiriladi.
- A'zoni o'chirish uning barcha topshiriqlarini ham o'chiradi.
