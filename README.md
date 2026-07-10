# Mini File Manager IDE

[![PHP Version](https://img.shields.io/badge/PHP-7.4%2B-8892bf.svg?style=flat-square)](https://www.php.net/)
[![Editor Engine](https://img.shields.io/badge/Editor-Monaco-007acc.svg?style=flat-square)](https://microsoft.github.io/monaco-editor/)
[![Styling UI](https://img.shields.io/badge/UI-Tailwind_CSS-38bdf8.svg?style=flat-square)](https://tailwindcss.com/)
[![GitHub License](https://img.shields.io/badge/License-MIT-green.svg?style=flat-square)](LICENSE)

> Mini File Manager IDE adalah ekosistem manajemen file dan web-based development environment (IDE) berbasis PHP native yang ringkas, berkinerja tinggi, dan berjalan dalam satu file tunggal (*single-file architecture*). 
>
> Dirancang menggunakan **Monaco Editor** dan **Tailwind CSS**, aplikasi ini menawarkan pengalaman coding kelas *cloud-IDE* yang responsif tanpa membutuhkan dependensi berat (zero-bloat). Dilengkapi dengan manajemen multi-user berbasis *Flat-File Secure Storage*, perlindungan SSRF/CSRF tingkat lanjut, serta sistem perluasan fungsi berbasis **IDE Hook Plugin Engine**.

<sub>**Perhatian!** _Hindari menggunakan skrip ini sebagai file manager standar di ruang publik tanpa konfigurasi proteksi IP/kredensial yang ketat. Sangat disarankan untuk membersihkan atau mengamankan skrip dari server setelah tugas pemeliharaan selesai dilakukan._</sub>

## Kebutuhan Sistem (Requirements)

- **PHP 7.4** atau versi yang lebih tinggi (Sangat optimal pada PHP 8.x).
- Ekstensi PHP berikut sangat direkomendasikan untuk fungsionalitas penuh:
  - `cURL` (Dibutuhkan untuk fitur download file via URL/Remote Download).
  - `ZipArchive` (Dibutuhkan untuk fitur kompresi batch ZIP & download terpadu).
  - `Fileinfo` & `mbstring` (Dibutuhkan untuk deteksi MIME-type media secara akurat).

## Cara Penggunaan (How to Use)

1. Unduh atau salin kode skrip `miniidemanager.php` ke dalam direktori *webspace* / *hosting* server Anda.
2. Anda dibebaskan untuk mengubah nama file dari `miniidemanager.php` menjadi nama unik lain (misal: `secret_ide.php`) untuk meningkatkan keamanan obfuscation.
3. Kredensial masuk sistem bawaan (*Default Credentials*):
   - **Username:** `admin`
   - **Password:** `admin123`

⚠️ **Peringatan Penting:** *Segera ganti password bawaan Anda langsung melalui menu **Settings** di dalam aplikasi setelah pertama kali berhasil masuk sistem. Password dienkripsi menggunakan standar industri keamanan `password_hash()`.*

💡 **Info Tambahan:** - Untuk mengaktifkan mode pemirsa publik, Anda dapat mengaktifkan **Guest Mode Access** di panel pengaturan, sehingga aplikasi dapat diakses publik secara aman via parameter query `?embed=1` dalam koridor akses *Read-Only*.

---

### 📢 Fitur Utama (Features)

- 💾 **Single-File Architecture:** Berjalan penuh hanya dengan satu file skrip utama. Minimalis, portabel, dan sangat mudah dipasang.
- 📱 **Responsive UI / Mobile Friendly:** Tampilan antarmuka yang modern dan responsif menggunakan Tailwind CSS, dioptimalkan untuk perangkat layar sentuh dan desktop.
- ⚙️ **Monaco Code Editor Engine:** Dilengkapi editor teks VS Code-like terintegrasi yang mendukung pencarian canggih (*Find & Replace* via `Ctrl+F` / `Ctrl+H`), pemetaan bahasa, dan indikator penyimpanan dinamis (*unsaved pulse detection*).
- 🧩 **IDE Hook Plugin Engine:** Memiliki arsitektur manajemen ekstensi sendiri via folder `/plugins`. Developer dapat menyisipkan file `backend.php`, `frontend.js`, dan `style.css` custom yang otomatis terpetakan ke sistem inti melalui fungsi `window.IDEHooks`.
- 📁 **Batch Operations:** Mengizinkan pemilihan banyak item (*Multi-Select Mode*) sekaligus untuk melakukan operasi massal seperti salin (*Copy*), pindah (*Move*), atau kompresi ZIP terenkapsulasi secara aman.
- 🖥️ **Media Preview Documents:** Dilengkapi pemutar media bawaan untuk menampilkan gambar, video, dan berkas audio, serta *isolated contextual iframe embedding* untuk dokumen PDF atau sejenisnya.
- 🛡️ **Advanced Security Shield:** - **Flat-File JSON Protection:** Berkas database sensitif (`.app_users.php`, `.app_config.php`) diproteksi dari akses langsung peretas via web menggunakan penutup skrip die-executable (`<?php exit("Access Denied"); ?>`).
  - **SSRF Protection:** Mengaudit resolusi DNS target pada unduhan jarak jauh untuk mencegah eksploitasi jaringan privat/internal server serta memblokir port berbahaya (seperti 22, 3306, 6379).
  - **CSRF Verification & Rate Limiting:** Validasi ketat token mutasi state via HTTP Header (`X-CSRF-Token`) dan sistem penguncian login otomatis (Brute-Force Lockout) berbasis IP per 5 percobaan gagal.
- 🎨 **Real-time Theme Synchronization:** Pilihan tema antarmuka dinamis (*Dark, Light, Ocean*) yang tersinkronisasi secara instan di seluruh tab browser maupun *local storage* secara *real-time*.

---

## Lisensi & Kredit

- Tersedia di bawah lisensi **MIT License**.
- Pengembangan UI & Sistem Inti menggunakan pustaka pihak ketiga via CDN: *Tailwind CSS, Monaco Editor, Tabler Icons.*
- Untuk melaporkan masalah (*Bug*) atau meminta fitur baru, silakan ajukan melalui menu [Issues](javascript:void(0);) di repositori ini.
