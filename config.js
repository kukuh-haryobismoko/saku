/* ============================================================
   KONFIGURASI SAKU
   ------------------------------------------------------------
   Email tujuan kode reset, pengirim email, & sinkronisasi cloud.
   Lihat README.md.
   ============================================================ */
window.SAKU_CONFIG = {
  // Email yang menerima kode reset:
  resetEmail: "bbkukuh@gmail.com",

  // Access key dari https://web3forms.com (gratis).
  web3formsKey: "fe539c0a-6597-4180-bb4f-c54bd3a0b271",

  /* ----------------------------------------------------------
     SINKRONISASI CLOUD (opsional) — agar data bisa dibuka di
     perangkat mana pun. Hanya isi bagian NON-RAHASIA di sini
     (owner/repo/path/branch). TOKEN TIDAK ditaruh di sini —
     token ditempel di aplikasi (Pengaturan → Sinkronisasi) dan
     hanya tersimpan di perangkat masing-masing.

     Buat repo PRIVAT khusus data (mis. "saku-data"), lalu isi:
  ---------------------------------------------------------- */
  sync: {
    owner:  "",            // username GitHub Anda, mis. "bbkukuh"
    repo:   "",            // repo PRIVAT untuk data, mis. "saku-data"
    path:   "vault.json",  // nama file penyimpan data terenkripsi
    branch: "main"
  }
};
