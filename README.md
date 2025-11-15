# 🚀 Cloudflare Workers Auto-Deployer

> **Automasi deployment Cloudflare Workers dengan multi-domain routing yang powerful dan mudah digunakan**

[![GitHub Actions](https://img.shields.io/badge/GitHub-Actions-2088FF?style=for-the-badge&logo=github-actions&logoColor=white)](https://github.com/features/actions)
[![Cloudflare](https://img.shields.io/badge/Cloudflare-Workers-F38020?style=for-the-badge&logo=cloudflare&logoColor=white)](https://workers.cloudflare.com/)

---

## 📖 Deskripsi

Repository ini menyediakan dua workflow GitHub Actions yang dirancang untuk mempermudah deployment Cloudflare Workers dengan konfigurasi multi-domain secara otomatis. Kedua workflow ini menggunakan pendekatan berbeda untuk memenuhi kebutuhan deployment yang beragam.

### ✨ Fitur Utama

- 🎯 **Deploy Single Worker** - Deployment cepat untuk satu worker dengan multiple routes
- 🔄 **Deploy Multiple Workers** - Deployment bertahap untuk banyak workers sekaligus
- 🌐 **Multi-Domain Support** - Kelola ratusan domain dan subdomain dengan mudah
- ⚡ **Zero Configuration** - File konfigurasi dibuat otomatis dari input
- 🛡️ **Safe Deployment** - Built-in delay untuk mencegah rate limiting

---

## 🎭 Dua Workflow, Dua Kekuatan

### 1️⃣ Deploy Injektor (`main.yml`)

**Single Worker, Multiple Domains**

Workflow ini ideal untuk mendeploy satu Cloudflare Worker yang akan menangani satu domain utama beserta beberapa subdomain.

#### 🎪 Kapan Menggunakan?

- ✅ Anda memiliki **satu domain utama** dengan beberapa subdomain
- ✅ Semua traffic akan ditangani oleh **satu worker yang sama**
- ✅ Deployment **cepat dan sederhana**
- ✅ Testing dan development

#### 🎬 Cara Penggunaan

1. **Siapkan File Konfigurasi**

   Buat file `customdomain.txt` di root repository dengan format:
   ```
   ava.game.naver.com
   quiz.int.vidio.com
   support.zoom.us
   cache.netflix.com

   ```

2. **Trigger Workflow**

   - Buka tab **Actions** di repository GitHub
   - Pilih **"Deploy Injektor"**
   - Klik **"Run workflow"**
   - Isi form input:

   | Parameter | Deskripsi | Contoh |
   |-----------|-----------|--------|
   | `worker_name` | Nama unik worker | `my-awesome-worker` |
   | `cloudflare_account_id` | Account ID Cloudflare | `abc123def456...` |
   | `cloudflare_api_token` | API Token dengan izin edit Workers | `xxxxx-yyyyyyy-zzzzz` |
   | `main_domain` | Domain utama | `example.com` |

3. **Hasil Deployment**

   Worker akan di-deploy dengan routes:
   ```
   ✓ example.com
   ✓ ava.game.naver.com.example.com
   ✓ quiz.int.vidio.com.example.com
   ✓ support.zoom.us.example.com
   ✓ cache.netflix.com.example.com
   ```

---

### 2️⃣ Deploy Chunked Multi-Domain Worker (`multi.yml`)

**Multiple Workers, Massive Scale**

Workflow ini dirancang untuk deployment skala besar dengan kemampuan mendeploy banyak workers sekaligus, masing-masing untuk domain utama yang berbeda.

#### 🎪 Kapan Menggunakan?

- ✅ Anda memiliki **banyak domain utama** yang berbeda
- ✅ Setiap domain memerlukan **worker terpisah**
- ✅ Deployment **massal dan efisien**
- ✅ Multi-tenant applications
- ✅ Deployment production scale

#### 🎬 Cara Penggunaan

1. **Siapkan File Konfigurasi**

   **File 1:** `main_domains.txt` - Daftar domain utama
   ```
   blueivy.qzz.io
   taylor.swift.net
   ariana.grande.dev
   ```

   **File 2:** `customdomain.txt` - Daftar prefix subdomain (sama seperti workflow pertama)
   ```
   ava.game.naver.com
   quiz.int.vidio.com
   support.zoom.us
   cache.netflix.com
   ```

2. **Trigger Workflow**

   - Buka tab **Actions** di repository GitHub
   - Pilih **"Deploy Chunked Multi-Domain Worker"**
   - Klik **"Run workflow"**
   - Isi form input:

   | Parameter | Deskripsi | Default | Contoh |
   |-----------|-----------|---------|--------|
   | `cloudflare_account_id` | Account ID Cloudflare | - | `abc123def456...` |
   | `cloudflare_api_token` | API Token dengan izin edit Workers | - | `xxxxx-yyyyyyy-zzzzz` |
   | `chunk_size` | Jumlah domain per deployment | `1` | `1` (recommended) |

3. **Proses Deployment**

   Workflow akan:
   ```
   📦 Membaca main_domains.txt
   ⚡ Split menjadi chunks
   🔄 Loop untuk setiap domain utama:
      ├─ Generate worker name otomatis (dari domain)
      ├─ Buat wrangler.toml dinamis
      ├─ Deploy worker
      └─ Tunggu 20 detik (anti rate-limit)
   ✅ Selesai!
   ```

4. **Hasil Deployment**

   Dari contoh di atas, akan ter-deploy 3 workers:

   **Worker: `blueivy`**
   ```
   ✓ blueivy.qzz.io
   ✓ ava.game.naver.com.blueivy.qzz.io
   ✓ quiz.int.vidio.com.blueivy.qzz.io
   ✓ support.zoom.us.blueivy.qzz.io
   ✓ cache.netflix.com.blueivy.qzz.io
   ```

   **Worker: `taylor`**
   ```
   ✓ taylor.swift.net
   ✓ ava.game.naver.com.taylor.swift.net
   ✓ quiz.int.vidio.com.taylor.swift.net
   ✓ support.zoom.us.taylor.swift.net
   ✓ cache.netflix.com.taylor.swift.net
   ```

   **Worker: `ariana`**
   ```
   ✓ ariana.grande.dev
   ✓ ava.game.naver.com.ariana.grande.dev
   ✓ quiz.int.vidio.com.ariana.grande.dev
   ✓ support.zoom.us.ariana.grande.dev
   ✓ cache.netflix.com.ariana.grande.dev
   ```

---

## 🔐 Setup Cloudflare API Token

Untuk menggunakan kedua workflow ini, Anda memerlukan Cloudflare API Token dengan permission yang tepat:

1. Login ke [Cloudflare Dashboard](https://dash.cloudflare.com/)
2. Pergi ke **My Profile** → **API Tokens**
3. Klik **Create Token**
4. Gunakan template **Edit Cloudflare Workers** atau buat custom dengan permissions:
   - Account → Workers Scripts → Edit
   - Account → Workers Routes → Edit
   - Zone → Workers Routes → Edit (jika menggunakan custom domain)
5. Copy token yang dihasilkan

### 📍 Mendapatkan Account ID

Account ID bisa ditemukan di:
- Dashboard Cloudflare → Pilih domain → Sidebar kanan bawah
- Atau di URL: `https://dash.cloudflare.com/[ACCOUNT_ID]/workers`

---

## 📂 Struktur File

```
your-repository/
├── .github/
│   └── workflows/
│       ├── main.yml              # Deploy Injektor
│       └── multi.yml             # Deploy Chunked Multi-Domain
├── worker.js                     # Kode Cloudflare Worker Anda
├── customdomain.txt              # Daftar subdomain prefix
├── main_domains.txt              # (untuk multi.yml) Daftar domain utama
└── README.md                     # Dokumentasi ini
```

---

## 🎯 Perbandingan Workflow

| Fitur | Deploy Injektor | Deploy Multi-Domain |
|-------|----------------|---------------------|
| **Jumlah Worker** | 1 | Banyak (dinamis) |
| **Domain Utama** | 1 (manual input) | Banyak (dari file) |
| **Naming Worker** | Manual | Otomatis dari domain |
| **Use Case** | Development/Single App | Production/Multi-tenant |
| **Kompleksitas** | Rendah | Sedang |
| **Kecepatan** | Cepat | Bertahap (dengan delay) |
| **Rate Limiting Protection** | ❌ | ✅ (20s delay) |

---

## 💡 Tips & Best Practices

### ✅ DO's

- 🔒 Simpan API Token sebagai **GitHub Secrets** jika deployment otomatis
- 📝 Gunakan nama worker yang **deskriptif dan unik**
- 🧪 Test dengan satu domain dulu sebelum deployment massal
- ⏱️ Pertahankan `chunk_size: 1` untuk menghindari rate limiting
- 📋 Backup file `main_domains.txt` dan `customdomain.txt`

### ❌ DON'Ts

- 🚫 Jangan commit API Token ke repository
- 🚫 Jangan gunakan chunk_size > 1 tanpa testing
- 🚫 Jangan deploy tanpa validasi `worker.js`
- 🚫 Jangan lupa menambahkan newline di akhir file `.txt`

---

## 🐛 Troubleshooting

### Problem: "File main_domains.txt tidak ditemukan"

**Solusi:** Pastikan file ada di root repository dan sudah di-commit.

### Problem: "Deployment failed - Rate Limited"

**Solusi:**
- Gunakan `chunk_size: 1`
- Increase delay di script (ubah `sleep 20` menjadi `sleep 30`)

### Problem: "Invalid wrangler.toml"

**Solusi:**
- Pastikan tidak ada baris kosong di akhir file `.txt`
- Check format domain (harus valid FQDN)

### Problem: "Worker name already exists"

**Solusi:**
- Deploy Injektor: Gunakan nama worker yang berbeda
- Deploy Multi-Domain: Worker name otomatis dari domain, pastikan domain unik

---

## 🤝 Contributing

Contributions are welcome! Jangan ragu untuk:

- 🐛 Report bugs
- 💡 Suggest new features
- 📖 Improve documentation
- 🔧 Submit pull requests

---

## 📜 License

Silakan sesuaikan dengan lisensi project Anda.

---

## 🎉 Acknowledgments

- **Cloudflare** - Untuk platform Workers yang luar biasa
- **GitHub Actions** - Untuk CI/CD yang powerful
- **Wrangler** - CLI tool yang memudahkan deployment

---

<div align="center">

**Made BY AFRCloud-NET**

[⬆ Back to Top](#-cloudflare-workers-auto-deployer)

</div>
