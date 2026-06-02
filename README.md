# Auth (Sign up / Sign in) untuk situs

File yang ditambahkan:

- `signup.html` — halaman frontend untuk mendaftar
- `signin.html` — halaman frontend untuk login
- `server.js` — backend minimal (Express + SQLite)
- `package.json` — script start

Cara menjalankan (di folder project):

```bash
npm init -y    # jika belum ada
npm install express sqlite3 bcryptjs jsonwebtoken
node server.js
```

Buka `http://localhost:3000/signup.html` atau `signin.html` untuk mencoba.
Halaman admin baru:
+- `admin.html` — panel admin untuk upload file dan link informasi.
+- Hanya dapat digunakan setelah login dan backend berjalan.
Catatan keamanan:
- Atur `JWT_SECRET` di environment pada production.
- Gunakan HTTPS dan cookie HttpOnly jika perlu.
