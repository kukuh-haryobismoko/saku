# Saku — Catatan Keuangan Pribadi

Aplikasi keuangan pribadi statis (HTML/CSS/JS murni). Tanpa server, tanpa _build step_.
Mencatat pengeluaran, pemasukan, transfer antar akun, pembayaran kartu kredit, dan
investasi — dengan kekayaan bersih yang dihitung otomatis.

- **Terenkripsi.** Data dikunci kata sandi dan dienkripsi (AES‑256) di perangkat Anda.
- **Tombol & form.** Tambah / ubah / hapus transaksi & sumber dana langsung dari layar.
- **Logo akun.** Tiap akun punya monogram berwarna (BCA, BRI, Shopee, Bibit, dst).
- **Reset aman.** Reset ke nol memerlukan kode konfirmasi yang dikirim ke email Anda.

---

## 1. Jalankan / Deploy

### Cara cepat (GitHub Pages)
1. Buat repository baru di GitHub, mis. `saku`.
2. Unggah semua isi folder ini (`index.html`, `config.js`, folder `assets/`, dll).
3. Buka **Settings → Pages**, pilih branch `main`, folder `/ (root)`, **Save**.
4. Tunggu ±1 menit. Situs aktif di `https://<username>.github.io/saku/`.

> Wajib lewat **https** (GitHub Pages) atau **localhost** — enkripsi (Web Crypto)
> hanya aktif di koneksi aman.

### Coba di komputer (localhost)
```bash
cd saku
python3 -m http.server 8000
# buka http://localhost:8000
```

---

## 2. Atur Email Kode Reset

Reset data memerlukan kode yang dikirim ke **bbkukuh@gmail.com**. Pengirimannya
memakai layanan gratis **Web3Forms**:

1. Buka <https://web3forms.com>, masukkan email **bbkukuh@gmail.com**, klik buat akses.
2. Web3Forms mengirim sebuah **Access Key** ke email itu — salin.
3. Buka file **`config.js`**, tempel ke `web3formsKey`:
   ```js
   window.SAKU_CONFIG = {
     resetEmail: "bbkukuh@gmail.com",
     web3formsKey: "TEMPEL-ACCESS-KEY-DI-SINI"
   };
   ```
4. Commit & push. Selesai — kode reset kini terkirim ke email Anda.

> Belum diatur? Fitur reset tetap aman: ia akan menawarkan reset dengan **kata sandi**
> sebagai cadangan, dan tidak akan menolkan data tanpa konfirmasi.

Access key Web3Forms aman ditaruh di kode klien (dibatasi domain & rate‑limit), jadi
boleh ikut di‑commit.

---

## 3. Masukkan Data Awal (opsional)

Agar repo publik tidak memuat saldo pribadi, aplikasi mulai dari **template kosong**
(saldo 0). Untuk memuat data contoh Anda:

1. Buka aplikasi, buat kata sandi.
2. Ikon **⚙ → Impor cadangan**, pilih file **`starter-data.json`**.

`starter-data.json` **tidak ikut di‑commit** (ada di `.gitignore`) demi privasi.
Simpan baik‑baik sebagai cadangan.

---

## 4. Keamanan — yang perlu dipahami

- Kata sandi Anda menurunkan kunci AES‑256 (PBKDF2, 200rb iterasi). Seluruh data
  disimpan sebagai **ciphertext** di `localStorage`. Tanpa kata sandi, isinya tak terbaca.
- **Lupa kata sandi = data tidak bisa dipulihkan.** Rutin **Unduh cadangan** (⚙ → Unduh).
- Ini aplikasi sisi‑klien: keamanannya melindungi **data tersimpan**, bukan mencegah
  seseorang yang memegang perangkat tak‑terkunci. Untuk keamanan maksimal, host di
  repo **privat** dan kunci perangkat Anda.
- Data tersimpan **per browser/perangkat**. Pindah perangkat → pakai Unduh/Impor cadangan.

---

## 5. Struktur Berkas

```
saku/
├── index.html          Halaman utama + layar kunci
├── config.js           Email & access key (Anda isi)
├── assets/
│   ├── styles.css      Gaya tampilan
│   └── app.js          Logika, enkripsi, reset, impor/ekspor
├── starter-data.json   Data awal (opsional, tidak di‑commit)
├── README.md
├── LICENSE
└── .gitignore
```

## Lisensi
MIT — lihat `LICENSE`.
