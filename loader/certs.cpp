// certs.cpp - the local proxy's own TLS certificate.
//
// One self-signed RSA certificate+key, generated once and cached in the game
// folder (ff7ec_proxy.pfx). It is used only as the TLS *server* certificate
// the local decrypting proxy presents back to the game on 127.0.0.1 - it
// signs nothing else and is not a CA. install_ca_to_user_root() is a separate,
// opt-in step for the user who also wants some other local app to trust it.
#include "loader.h"
#include <wincrypt.h>
#include <ncrypt.h>
#include <string>
#include <vector>

#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "ncrypt.lib")

namespace loader {

static PCCERT_CONTEXT g_cert = nullptr;
static std::wstring g_cert_path;
// Local-machine-only passphrase protecting the cached private key file; the
// key is never used for anything beyond this loopback proxy.
static const wchar_t* kPfxPassword = L"ff7ec-preservation-local-proxy";

std::wstring identity_cert_path() { return g_cert_path; }
void* identity_cert_context() { return (void*)g_cert; }

static PCCERT_CONTEXT load_from_pfx(const std::wstring& path) {
    HANDLE f = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
    if (f == INVALID_HANDLE_VALUE) return nullptr;
    DWORD size = GetFileSize(f, nullptr);
    std::string buf(size, '\0');
    DWORD read = 0;
    BOOL ok = size && size != INVALID_FILE_SIZE && ReadFile(f, buf.data(), size, &read, nullptr);
    CloseHandle(f);
    if (!ok || read != size) return nullptr;

    CRYPT_DATA_BLOB blob{(DWORD)buf.size(), (BYTE*)buf.data()};
    if (!PFXIsPFXBlob(&blob)) return nullptr;
    HCERTSTORE store = PFXImportCertStore(&blob, kPfxPassword, CRYPT_EXPORTABLE);
    if (!store) return nullptr;
    PCCERT_CONTEXT ctx = CertFindCertificateInStore(store, X509_ASN_ENCODING, 0, CERT_FIND_ANY, nullptr, nullptr);
    PCCERT_CONTEXT dup = ctx ? CertDuplicateCertificateContext(ctx) : nullptr;
    CertCloseStore(store, 0);
    return dup;
}

static bool save_to_pfx(PCCERT_CONTEXT cert, const std::wstring& path) {
    HCERTSTORE store = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, 0, nullptr);
    if (!store) return false;
    bool ok = CertAddCertificateContextToStore(store, cert, CERT_STORE_ADD_ALWAYS, nullptr);
    CRYPT_DATA_BLOB blob{0, nullptr};
    if (ok) ok = PFXExportCertStore(store, &blob, kPfxPassword, EXPORT_PRIVATE_KEYS);
    if (ok) {
        std::string buf(blob.cbData, '\0');
        blob.pbData = (BYTE*)buf.data();
        ok = PFXExportCertStore(store, &blob, kPfxPassword, EXPORT_PRIVATE_KEYS);
        if (ok) {
            HANDLE f = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, 0, nullptr);
            if (f != INVALID_HANDLE_VALUE) {
                DWORD written = 0;
                ok = WriteFile(f, buf.data(), (DWORD)buf.size(), &written, nullptr) && written == buf.size();
                CloseHandle(f);
            } else ok = false;
        }
    }
    CertCloseStore(store, 0);
    return ok;
}

// Generates one self-signed RSA-2048 certificate, valid for the subject CN
// "FF7EC Preservation Local Proxy" plus a loopback SAN, 10-year lifetime.
static PCCERT_CONTEXT generate_self_signed() {
    NCRYPT_PROV_HANDLE prov = 0;
    if (NCryptOpenStorageProvider(&prov, MS_KEY_STORAGE_PROVIDER, 0) != ERROR_SUCCESS) return nullptr;
    NCRYPT_KEY_HANDLE key = 0;
    // Ephemeral, in-memory key: never persisted to the Windows key store, only
    // ever exported into our own local .pfx file below.
    NCryptCreatePersistedKey(prov, &key, NCRYPT_RSA_ALGORITHM, nullptr, 0, NCRYPT_OVERWRITE_KEY_FLAG);
    DWORD bits = 2048;
    NCryptSetProperty(key, NCRYPT_LENGTH_PROPERTY, (PBYTE)&bits, sizeof(bits), 0);
    if (NCryptFinalizeKey(key, 0) != ERROR_SUCCESS) { NCryptFreeObject(key); NCryptFreeObject(prov); return nullptr; }

    CERT_NAME_BLOB subject{0, nullptr};
    const wchar_t* name = L"CN=FF7EC Preservation Local Proxy";
    DWORD enc_len = 0;
    CertStrToNameW(X509_ASN_ENCODING, name, CERT_X500_NAME_STR, nullptr, nullptr, &enc_len, nullptr);
    std::vector<BYTE> enc(enc_len);
    CertStrToNameW(X509_ASN_ENCODING, name, CERT_X500_NAME_STR, nullptr, enc.data(), &enc_len, nullptr);
    subject.cbData = enc_len; subject.pbData = enc.data();

    CRYPT_KEY_PROV_INFO kp{};
    CERT_EXTENSIONS exts{0, nullptr};
    SYSTEMTIME start, end;
    GetSystemTime(&start);
    end = start; end.wYear += 10;

    PCCERT_CONTEXT cert = CertCreateSelfSignCertificate(
        key, &subject, 0, &kp, nullptr, &start, &end, &exts);
    NCryptFreeObject(key);
    NCryptFreeObject(prov);
    return cert;
}

bool identity_init(const std::wstring& dir) {
    g_cert_path = dir + L"\\ff7ec_proxy.pfx";
    g_cert = load_from_pfx(g_cert_path);
    if (g_cert) { logf("certs: loaded cached proxy certificate from %ls", g_cert_path.c_str()); return true; }

    g_cert = generate_self_signed();
    if (!g_cert) { logf("certs: FATAL - could not generate the local proxy certificate"); return false; }
    if (!save_to_pfx(g_cert, g_cert_path))
        logf("certs: generated a proxy certificate but could not cache it at %ls (will regenerate next run)",
             g_cert_path.c_str());
    else
        logf("certs: generated and cached a new proxy certificate at %ls", g_cert_path.c_str());
    return true;
}

bool install_ca_to_user_root() {
    if (!g_cert) return false;
    HCERTSTORE root = CertOpenStore(CERT_STORE_PROV_SYSTEM_W, 0, 0, CERT_SYSTEM_STORE_CURRENT_USER, L"Root");
    if (!root) { logf("certs: could not open CurrentUser\\Root"); return false; }
    bool ok = CertAddCertificateContextToStore(root, g_cert, CERT_STORE_ADD_REPLACE_EXISTING, nullptr);
    CertCloseStore(root, 0);
    logf("certs: %s adding proxy certificate to CurrentUser\\Root (opt-in via [mitm] install_ca)",
         ok ? "finished" : "failed");
    return ok;
}

}  // namespace loader
