import asyncio
import ipaddress
import os
import re
import shutil
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.types import (
    CertificateIssuerPrivateKeyTypes,
)
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

app = FastAPI()
templates = Jinja2Templates(directory="templates")

# Static files (CSS)
app.mount("/static", StaticFiles(directory="static"), name="static")

CERT_DIR = Path(os.getenv("LOCAL_CA_PATH", "/local-ca"))
FILE_DIR = Path(os.getenv("LOCAL_DATA_PATH", "/data"))
CA_CERT = CERT_DIR / "ca.pem"
CA_KEY = CERT_DIR / "ca.key"

# Regex für sichere Dateinamen: alphanumerisch, Bindestrich, Unterstrich, Punkt
SAFE_NAME_PATTERN = re.compile(r'^[a-zA-Z0-9._-]+$')

# Verfügbare Schlüsseltypen: (value, label, generator_function)
KEY_TYPES = [
    ("rsa2048", "RSA 2048", lambda: rsa.generate_private_key(public_exponent=65537, key_size=2048)),
    ("rsa4096", "RSA 4096", lambda: rsa.generate_private_key(public_exponent=65537, key_size=4096)),
    ("secp256r1", "ECC SECP256R1 (P-256)", lambda: ec.generate_private_key(ec.SECP256R1())),
    ("secp384r1", "ECC SECP384R1 (P-384)", lambda: ec.generate_private_key(ec.SECP384R1())),
    ("secp521r1", "ECC SECP521R1 (P-521)", lambda: ec.generate_private_key(ec.SECP521R1())),
]

# Lookup-Dict für schnellen Zugriff
KEY_TYPE_GENERATORS = {kt[0]: kt[2] for kt in KEY_TYPES}


def validate_safe_name(name: str) -> bool:
    return bool(SAFE_NAME_PATTERN.match(name)) and ".." not in name


def key_type_label(public_key) -> str:
    if isinstance(public_key, rsa.RSAPublicKey):
        return f"RSA {public_key.key_size}"
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        return f"ECC {public_key.curve.name}"
    return type(public_key).__name__


def key_type_value(public_key) -> str | None:
    """Ermittelt den passenden KEY_TYPES-value für ein Formular-Prefill."""
    if isinstance(public_key, rsa.RSAPublicKey):
        if public_key.key_size == 2048:
            return "rsa2048"
        if public_key.key_size == 4096:
            return "rsa4096"
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        curve_name = public_key.curve.name
        if curve_name in ("secp256r1", "secp384r1", "secp521r1"):
            return curve_name
    return None


def parse_san_entry(entry: str):
    """Parst einen SAN-Eintrag und gibt das passende x509-Objekt zurück (DNSName oder IPAddress)."""
    try:
        ip = ipaddress.ip_address(entry)
        return x509.IPAddress(ip)
    except ValueError:
        return x509.DNSName(entry)


def generate_key(key_type: str):
    """Generiert einen privaten Schlüssel basierend auf dem Typ."""
    if key_type not in KEY_TYPE_GENERATORS:
        raise HTTPException(status_code=400, detail=f"Ungültiger Schlüsseltyp: {key_type}")
    return KEY_TYPE_GENERATORS[key_type]()


def build_name(organization: str, common_name: str) -> x509.Name:
    return x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "DE"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Germany"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "LAN"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]
    )


async def save_cert_files(
    host_dir: Path,
    hostname: str,
    cert_bytes: bytes,
    key_bytes: bytes,
    ca_cert_bytes: bytes,
) -> None:
    cert_path = host_dir / f"{hostname}.crt"
    fullchain_path = host_dir / f"{hostname}.fullchain.crt"
    key_path = host_dir / f"{hostname}.key"
    combined_path = host_dir / f"{hostname}.pem"

    await asyncio.to_thread(cert_path.write_bytes, cert_bytes)
    await asyncio.to_thread(fullchain_path.write_bytes, cert_bytes + ca_cert_bytes)
    await asyncio.to_thread(key_path.write_bytes, key_bytes)
    await asyncio.to_thread(combined_path.write_bytes, key_bytes + cert_bytes)


@app.get("/", response_class=HTMLResponse)
async def form(request: Request, hostname: str | None = None):
    ca_exists = CA_CERT.exists() and CA_KEY.exists()
    context = {
        "ca_exists": ca_exists,
        "key_types": KEY_TYPES,
    }

    # Vorbefüllung des Formulars für "Erneuern" aus der Zertifikatsliste
    if hostname and validate_safe_name(hostname):
        cert_path = FILE_DIR / hostname / f"{hostname}.crt"
        context["hostname"] = hostname
        if cert_path.exists():
            cert = x509.load_pem_x509_certificate(await asyncio.to_thread(cert_path.read_bytes))
            san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            dns_names = san_ext.value.get_values_for_type(x509.DNSName)
            ip_addrs = san_ext.value.get_values_for_type(x509.IPAddress)
            alt_entries = [n for n in dns_names if n != hostname] + [
                str(ip) for ip in ip_addrs if str(ip) != hostname
            ]
            context["alt_names"] = ", ".join(alt_entries)
            cert_key_type = key_type_value(cert.public_key())
            if cert_key_type:
                context["cert_key_type"] = cert_key_type

    return templates.TemplateResponse(request, "form.html", context)

@app.post("/", response_class=HTMLResponse)
async def create_cert(
    request: Request,
    hostname: str = Form(...),
    alt_names: str = Form(""),
    cert_key_type: str = Form(...),
    validity_days: int = Form(825)
):
    form_values = {
        "hostname": hostname,
        "alt_names": alt_names,
        "cert_key_type": cert_key_type,
        "validity_days": validity_days,
    }

    ca_exists = CA_CERT.exists() and CA_KEY.exists()

    def error_response(msg: str):
        return templates.TemplateResponse(
            request, "form.html",
            {"ca_exists": ca_exists, "key_types": KEY_TYPES, "error": msg, **form_values},
            status_code=400,
        )

    if not validate_safe_name(hostname):
        return error_response("Ungültiger Hostname.")

    if not ca_exists:
        return error_response("Bitte zuerst eine CA erstellen.")

    # Gültigkeit begrenzen (1 Tag bis 10 Jahre)
    validity_days = max(1, min(validity_days, 3650))

    alt_names_list = [n.strip() for n in alt_names.split(",") if n.strip()]

    # Key generieren
    key = generate_key(cert_key_type)

    host_dir = FILE_DIR / hostname
    host_dir.mkdir(parents=True, exist_ok=True)

    # CA laden
    ca_cert = x509.load_pem_x509_certificate(await asyncio.to_thread(CA_CERT.read_bytes))
    ca_key = serialization.load_pem_private_key(
        await asyncio.to_thread(CA_KEY.read_bytes), password=None
    )
    assert isinstance(ca_key, CertificateIssuerPrivateKeyTypes)

    # CSR bauen
    subject = build_name("Homelab", hostname)
    # SANs erstellen: Hostname + alternative Namen (DNS oder IP)
    alt_names_objs = [parse_san_entry(hostname)] + [
        parse_san_entry(n) for n in alt_names_list
    ]

    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(subject)
        .add_extension(x509.SubjectAlternativeName(alt_names_objs), critical=False)
        .sign(key, hashes.SHA256())
    )

    # KeyUsage je nach Schlüsseltyp: RSA braucht keyEncipherment, ECC keyAgreement
    public_key = csr.public_key()
    key_usage = x509.KeyUsage(
        digital_signature=True,
        key_encipherment=isinstance(public_key, rsa.RSAPublicKey),
        key_agreement=isinstance(public_key, ec.EllipticCurvePublicKey),
        content_commitment=False,
        data_encipherment=False,
        key_cert_sign=False,
        crl_sign=False,
        encipher_only=False,
        decipher_only=False,
    )

    # Zertifikat signieren
    cert = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(ca_cert.subject)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC))
        .not_valid_after(datetime.now(UTC) + timedelta(days=validity_days))
        .add_extension(x509.SubjectAlternativeName(alt_names_objs), critical=False)
        .add_extension(key_usage, critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
        .sign(private_key=ca_key, algorithm=hashes.SHA256())
    )

    cert_bytes = cert.public_bytes(serialization.Encoding.PEM)
    key_bytes = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )

    cert_content = cert_bytes.decode()
    key_content = key_bytes.decode()
    ca_cert_bytes = ca_cert.public_bytes(serialization.Encoding.PEM)
    fullchain_content = cert_content + ca_cert_bytes.decode()

    # Zertifikat, Fullchain, Key und kombinierte PEM-Datei speichern
    await save_cert_files(host_dir, hostname, cert_bytes, key_bytes, ca_cert_bytes)

    # Ergebnis direkt unter dem Formular anzeigen
    return templates.TemplateResponse(
        request, "form.html",
        {
            "hostname": hostname,
            "cert_content": cert_content,
            "key_content": key_content,
            "fullchain_content": fullchain_content,
            "ca_exists": ca_exists,
            "key_types": KEY_TYPES,
        },
    )

@app.get("/download/{hostname}/{filename}")
async def download_file(hostname: str, filename: str):
    if not validate_safe_name(hostname) or not validate_safe_name(filename):
        raise HTTPException(status_code=400, detail="Ungültiger Hostname oder Dateiname")

    full_path = FILE_DIR / hostname / filename
    if not full_path.exists():
        raise HTTPException(status_code=404, detail="Datei nicht gefunden")

    return FileResponse(full_path, filename=filename)

@app.post("/delete/{hostname}")
async def delete_cert(hostname: str):
    if not validate_safe_name(hostname):
        raise HTTPException(status_code=400, detail="Ungültiger Hostname.")

    host_dir = FILE_DIR / hostname
    if host_dir.exists():
        await asyncio.to_thread(shutil.rmtree, host_dir)

    return RedirectResponse(url="/certs", status_code=303)


@app.get("/download-ca/{filename}")
async def download_ca(filename: str):
    if not validate_safe_name(filename):
        raise HTTPException(status_code=400, detail="Ungültiger Dateiname")

    if filename == "ca.key":
        raise HTTPException(status_code=403, detail="Der private CA-Schlüssel kann nicht heruntergeladen werden.")

    full_path = CERT_DIR / filename
    if not full_path.exists():
        raise HTTPException(status_code=404, detail="Datei nicht gefunden")

    return FileResponse(full_path, filename=filename)

@app.post("/create-ca", response_class=HTMLResponse)
async def create_ca(request: Request, ca_key_type: str = Form(...), ca_validity_days: int = Form(825)):
    CERT_DIR.mkdir(parents=True, exist_ok=True)

    # Key generieren
    key = generate_key(ca_key_type)

    # CA-Zertifikat erstellen
    subject = issuer = build_name("Homelab CA", "Homelab Root CA")

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC))
        .not_valid_after(datetime.now(UTC) + timedelta(days=max(1, min(ca_validity_days, 7300))))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                key_cert_sign=True,
                crl_sign=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )

    # Dateien speichern
    await asyncio.to_thread(
        CA_KEY.write_bytes,
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ),
    )

    await asyncio.to_thread(CA_CERT.write_bytes, cert.public_bytes(serialization.Encoding.PEM))

    return templates.TemplateResponse(
        request, "form.html", {
            "ca_created": True,
            "ca_exists": True,
            "key_types": KEY_TYPES,
        }
    )


@app.get("/ca-info", response_class=HTMLResponse)
async def ca_info(request: Request):
    ca_exists = CA_CERT.exists() and CA_KEY.exists()
    return templates.TemplateResponse(request, "ca_info.html", {"ca_exists": ca_exists})


@app.get("/certs", response_class=HTMLResponse)
async def list_certs(request: Request):
    now = datetime.now(UTC)
    certs = []
    if FILE_DIR.exists():
        for host_dir in sorted(FILE_DIR.iterdir()):
            if not host_dir.is_dir():
                continue
            cert_path = host_dir / f"{host_dir.name}.crt"
            if not cert_path.exists():
                continue
            cert = x509.load_pem_x509_certificate(await asyncio.to_thread(cert_path.read_bytes))
            expires = cert.not_valid_after_utc
            days_left = (expires - now).days
            certs.append({
                "hostname": host_dir.name,
                "expires": expires.strftime("%Y-%m-%d"),
                "days_left": days_left,
                "key_type": key_type_label(cert.public_key()),
            })
    return templates.TemplateResponse(request, "certs.html", {"certs": certs})


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=2000)
