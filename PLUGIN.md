
# 🧩 PLUGIN.md

```markdown
# 🧩 Panduan Memasang & Membuat Plugin (Aksesoris Tambahan)

Halo! Selamat datang di panduan plugin Mini File Manager IDE. 

Di proyek komunitas ini, kamu gak cuma bisa pakai fitur bawaan, tapi juga bisa nambahin fitur baru lewat yang namanya **Plugin**. Anggap saja plugin ini seperti "aksesoris" atau "mod" tambahan yang bisa dicolok ke aplikasi utama tanpa perlu ngerusak kode aslinya.

Panduan ini dibuat super simpel biar kamu yang awam atau baru belajar pun bisa langsung paham dan mempraktikkannya!

---

## 1. Cara Memasang Plugin Orang Lain (Buat User Awam)

Kalau kamu dapet folder plugin dari komunitas atau temen kamu, cara pasangnya gampang banget:

1. **Upload Folder:** Masuk ke cPanel/Hosting kamu, buka folder tempat kamu menaruh aplikasi ini, lalu cari folder bernama `plugins/`. Upload folder plugin baru kamu ke dalam folder `plugins/` tersebut.
2. **Masuk ke Aplikasi:** Buka Mini File Manager IDE kamu lewat browser, lalu login pake akun **Admin**.
3. **Nyalakan di Settings:** Klik ikon roda gigi (**Settings** ⚙️) di pojok kiri bawah. Gulir ke bawah sampai nemu bagian **Manajemen Plugin**.
4. **Geser Saklar ke ON:** Kamu bakal melihat nama plugin yang baru kamu upload tadi. Cukup klik tombol saklarnya sampai berubah jadi **ON**.
5. **Selesai!** Aplikasi bakal minta refresh halaman. Klik OK, dan fitur baru kamu sudah aktif!

---

## 2. Struktur Dasar Sebuah Plugin

Setiap plugin itu cuma berupa **satu folder** yang di dalamnya berisi file-file opsional berikut ini:

```text
plugins/
  └── nama-plugin-kamu/
        ├── backend.php     ← (Opsional) Kerjanya di server hosting (pake bahasa PHP)
        ├── frontend.js     ← (Opsional) Kerjanya di browser kamu (pake bahasa JavaScript)
        └── style.css       ← (Opsional) Buat ngatur warna/tampilan hiasan (pake CSS)

```

> 💡 **Info Menarik:** Plugin kamu gak harus punya ketiga file di atas. Kalau plugin kamu cuma buat ganti warna tombol, kamu cuma butuh file `style.css` aja di dalam foldernya. Bebas banget!

---

## 3. Yuk, Coba Bikin Plugin Sendiri! (Contoh Super Simpel)

Buat kamu yang pengen belajar, mari kita coba bikin plugin sederhana bernama **"pesan-halo"**. Plugin ini tugasnya cuma nampilin teks di halaman Settings.

### Langkah 1: Bikin Folder & File

Lewat file manager hosting kamu, masuk ke folder `plugins/`, lalu bikin folder baru bernama `pesan-halo`. Di dalam folder tersebut, bikin file baru bernama `frontend.js`.

### Langkah 2: Isi File `frontend.js`

Buka file `frontend.js` tadi, lalu copas kode simpel di bawah ini:

```javascript
// File: plugins/pesan-halo/frontend.js

// Kita minta izin ke sistem buat nambahin fungsi pas user buka tab/pindah halaman
window.IDEHooks.add('after_switchTab', function(activeTab, tabData) {
    
    // Kita cuma mau teks ini muncul pas user buka halaman Settings (⚙️)
    if (activeTab !== '__SETTINGS__') return;

    // Jaga-jaga biar teksnya gak muncul double/berlapis-lapis pas diklik ulang
    if (document.getElementById('teks-halo-komunitas')) return;

    // Cari tempat kosong di halaman Settings buat naruh teks kita
    const tempatNempel = document.getElementById('settings-plugin-mgmt');
    if (!tempatNempel) return;

    // Bikin kotak teks baru dengan tampilan keren bawaan Tailwind
    const kotakTeks = document.createElement('div');
    kotakTeks.id = 'teks-halo-komunitas';
    kotakTeks.className = 'bg-green-500/10 border border-green-500/30 text-green-400 p-4 rounded-xl mt-4 text-center font-bold';
    kotakTeks.innerText = '🎉 Keren! Plugin pertama buatanmu sendiri berhasil aktif!';
    
    // Tempel kotaknya di bawah menu manajemen plugin
    tempatNempel.insertAdjacentElement('afterend', kotakTeks);
});

```

### Langkah 3: Aktifkan!

Sekarang buka menu **Settings** di aplikasi kamu, cari plugin **Pesan halo**, lalu nyalain ke status **ON**. Lihat hasilnya di halaman Settings kamu!

---

## 🛠️ Tips Penting Buat yang Mau Belajar Lebih Dalam

Kalau kamu sudah mulai paham dan mau bikin logika yang lebih rumit, perhatikan 2 aturan emas ini ya:

### 1. Aturan Emas PHP (`backend.php`)

Kalau bikin fitur di file `backend.php` (sisi server), kamu **wajib** menuliskan kode `if (ob_get_length()) ob_clean();` sebelum mencetak data atau JSON. Ini penting banget biar datanya gak rusak atau pecah karena spasi kosong liar dari server.

### 2. Jangan Simpan Password di JavaScript (`frontend.js`)

Ingat ya, semua kode di file `frontend.js` bisa diintip oleh orang lain lewat menu *Inspect Element* di browser. Jadi, jangan pernah menaruh password, kunci rahasia, atau token API penting di dalam file JavaScript. Kalau butuh pengolahan data rahasia, oper operasinya ke file `backend.php`.

---

## 🎨 Variabel Warna Mengikuti Tema

Biar plugin kamu warnanya otomatis ikutan berubah pas user ganti tema (Gelap, Terang, atau Ocean), gunakan kode warna bawaan sistem ini di file `style.css` kamu:

* `var(--bg-main)` — Warna latar belakang utama.
* `var(--text-main)` — Warna teks utama.
* `var(--accent)` — Warna tombol aktif/aksen tema (biru/biru laut).

Selamat berkreasi dan mencoba bikin aksesoris versimu sendiri! Gak usah takut salah, namanya juga belajar bareng komunitas! 🤠🔥
