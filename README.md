# Mini File Manager IDE

[![PHP Version](https://img.shields.io/badge/PHP-7.4%2B-8892bf.svg?style=flat-square)](https://www.php.net/)
[![Editor Engine](https://img.shields.io/badge/Editor-Monaco-007acc.svg?style=flat-square)](https://microsoft.github.io/monaco-editor/)
[![Styling UI](https://img.shields.io/badge/UI-Tailwind_CSS-38bdf8.svg?style=flat-square)](https://tailwindcss.com/)
[![GitHub License](https://img.shields.io/badge/License-MIT-green.svg?style=flat-square)](LICENSE)

> **Proyek Publik Bebas Aturan!** 🚀
> Mini File Manager IDE adalah ekosistem manajemen file dan web-based IDE berbasis PHP native yang berjalan dalam satu file tunggal (*single-file architecture*). 
> 
> Proyek ini sepenuhnya milik publik. **Siapa aja boleh ambil, edit, rombak total, atau hancurin kodenya sebebas mungkin!** Nggak ada aturan birokrasi kaku, gak ada gatekeeping. Kalau kamu punya ide atau perbaikan, langsung tumpahin aja kodenya ke sini!

<sub>**Perhatian Bersama!** _Karena skrip ini sangat powerful, pastikan untuk selalu mengonfigurasi proteksi kredensial atau IP saat melakukan pengujian di server hidup. Jangan biarkan skrip terbuka tanpa pengamanan di server publik._</sub>

---

## 🤠 Bebas Ngapain Aja (Anarchy-Friendly)

Kami percaya kode terbaik itu lahir dari kebebasan penuh. Repositori ini gak punya aturan saklek buat kontribusi:

* **Mau Tambah Fitur?** Langsung coding, gak usah ribet mikirin nama branch yang bener.
* **Nemu Bug / Celah Security?** Langsung tambal kodenya, atau buka diskusi biar yang lain tahu.
* **Mau Bikin Tampilan Baru?** Silakan acak-acak Tailwind CSS-nya sampai berubah total sesuai selera kamu.
* **Mau Copas buat Proyek Sendiri?** Ambil aja, fork sepuasnya, rename sesuka hati, bebas!

*Yang penting kodenya jalan, bermanfaat, dan bikin hidup developer lain jadi lebih gampang.*

---

## 💡 Kebutuhan Sistem (Requirements)

- **PHP 7.4** atau versi yang lebih tinggi (Sangat optimal pada PHP 8.x).
- Ekstensi PHP berikut sangat direkomendasikan untuk membuka fungsionalitas penuh:
  - `cURL` (Untuk fitur Remote Download/URL Import).
  - `ZipArchive` (Untuk fitur kompresi batch ZIP).
  - `Fileinfo` & `mbstring` (Untuk deteksi tipe file/media).

---

## 🚀 Cara Penggunaan & Modifikasi

1. **Fork & Ambil Kodenya:** Klik tombol **Fork** di pojok kanan atas repositori ini buat punya salinan di akun kamu, atau langsung download file `miniidemanager.php`.
2. **Jalankan di Server:** Copas file `miniidemanager.php` ke dalam direktori server web kamu.
3. **Ganti Nama Sesukamu:** Kamu bebas mengubah nama file `miniidemanager.php` jadi apa aja (misal: `alat_rahasia.php`) biar gak gampang ditebak orang lain.
4. **Kredensial Bawaan (*Default*):**
   - **Username:** `admin`
   - **Password:** `admin123`

⚠️ **Tips:** *Jangan lupa langsung ganti password bawaan lewat menu **Settings** setelah berhasil login untuk pertama kali.*

---

## 📢 Fitur Utama (Features)

- 💾 **Single-File Power:** Seluruh sistem backend dan tampilan frontend dikemas dalam satu file skrip tunggal. Super portabel, tinggal drop dan jalankan di mana aja.
- 📱 **Modern & Responsive:** Antarmuka bersih menggunakan Tailwind CSS yang nyaman diakses baik dari smartphone, tablet, maupun desktop.
- ⚙️ **Monaco Code Editor Engine:** Pengalaman coding standar industri (seperti VS Code) lengkap dengan fitur pencarian canggih (*Find & Replace* via `Ctrl+F` / `Ctrl+H`), multi-tab manajemen, dan deteksi otomatis status penyimpanan berkas.
- 🧩 **Modular Plugin System:** Mendukung perluasan fungsi tanpa merusak kode inti via folder `/plugins`. Cukup manfaatkan engine hook `window.IDEHooks` lewat file `frontend.js` atau `backend.php` bikinanmu sendiri.
- 📁 **Massal Operations:** Mode multi-select untuk melakukan aksi massal seperti *Copy*, *Move*, atau *ZIP Compression* dalam sekali klik.
- 🖥️ **Media & Document Preview:** Pemutar langsung untuk file berbasis gambar, audio, video, hingga dokumen PDF secara instan di dalam editor.
- 🛡️ **Built-in Security Shield:** Proteksi flat-file database dari akses asing, pencegahan SSRF pada *remote download*, serta sistem verifikasi token CSRF untuk mengamankan mutasi data.

---

## 📄 Lisensi

Proyek ini menggunakan lisensi **MIT License**. Kamu bebas pakai, ubah, sebarin ulang, bahkan dijual lagi buat proyek komersial pun silakan, gak ada yang bakal nuntut!
