/* ============================================================
   SAKU CONFIGURATION
   ------------------------------------------------------------
   Reset code destination email, sender, & cloud sync.
   See README.md.
   ============================================================ */
window.SAKU_CONFIG = {
  // Email that receives the reset code:
  resetEmail: "bbkukuh@gmail.com",

  // Access key from https://web3forms.com (free).
  web3formsKey: "fe539c0a-6597-4180-bb4f-c54bd3a0b271",

  /* ----------------------------------------------------------
     CLOUD SYNC (optional) — so data can be opened on any
     device. Only fill in the NON-SECRET part here
     (owner/repo/path/branch). THE TOKEN DOES NOT go here —
     the token is pasted into the app (Settings → Sync) and
     is only stored on each individual device.

     Create a PRIVATE repo just for data (e.g. "saku-data"), then fill in:
  ---------------------------------------------------------- */
  sync: {
    owner:  "kukuh-haryobismoko",            // your GitHub username, e.g. "bbkukuh"
    repo:   "saku-data",            // PRIVATE repo for data, e.g. "saku-data"
    path:   "vault.json",  // file name for the encrypted data
    branch: "main"
  }
};
