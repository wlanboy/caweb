import os
import ipaddress
from pathlib import Path
from datetime import datetime, timedelta, timezone
import re
from fastapi import FastAPI, Form, Request, HTTPException
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec

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
    """Prüft ob ein Name sicher ist (keine Path Traversal Zeichen)."""
    return bool(SAFE_NAME_PATTERN.match(name)) and ".." not in name


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


@app.get("/", response_class=HTMLResponse)
async def form(request: Request):
    ca_exists = CA_CERT.exists() and CA_KEY.exists()
    return templates.TemplateResponse(
        "form.html", {
            "request": request,
            "ca_exists": ca_exists,
            "key_types": KEY_TYPES,
        }
    )

@app.post("/", response_class=HTMLResponse)
async def create_cert(
    request: Request,
    hostname: str = Form(...),
    alt_names: str = Form(""),
    cert_key_type: str = Form(...),
    validity_days: int = Form(825)
):
    ca_exists = CA_CERT.exists() and CA_KEY.exists()

    # Gültigkeit begrenzen (1 Tag bis 10 Jahre)
    validity_days = max(1, min(validity_days, 3650))

    alt_names_list = [n.strip() for n in alt_names.split(",") if n.strip()]

    # Key generieren
    key = generate_key(cert_key_type)

    host_dir = FILE_DIR / hostname
    host_dir.mkdir(parents=True, exist_ok=True)

    # CA laden
    with open(CA_CERT, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())
    with open(CA_KEY, "rb") as f:
        ca_key = serialization.load_pem_private_key(f.read(), password=None)

    # CSR bauen
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "DE"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Germany"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "LAN"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Homelab"),
            x509.NameAttribute(NameOID.COMMON_NAME, hostname),
        ]
    )
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

    # Zertifikat signieren
    cert = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(ca_cert.subject)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=validity_days))
        .add_extension(x509.SubjectAlternativeName(alt_names_objs), critical=False)
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

    # Zertifikat speichern
    cert_path = host_dir / f"{hostname}.crt"
    with open(cert_path, "wb") as f:
        f.write(cert_bytes)

    # Key-Datei speichern
    key_path = host_dir / f"{hostname}.key"
    with open(key_path, "wb") as f:
        f.write(key_bytes)

    # Kombinierte PEM-Datei (Key + Zertifikat)
    combined_path = host_dir / f"{hostname}.pem"
    with open(combined_path, "wb") as f:
        f.write(key_bytes)
        f.write(cert_bytes)

    # Ergebnis direkt unter dem Formular anzeigen
    return templates.TemplateResponse(
        "form.html",
        {
            "request": request,
            "hostname": hostname,
            "cert_content": cert_content,
            "key_content": key_content,
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
async def create_ca(request: Request, ca_key_type: str = Form(...)):
    CERT_DIR.mkdir(parents=True, exist_ok=True)

    # Key generieren
    key = generate_key(ca_key_type)

    # CA-Zertifikat erstellen
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "DE"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Germany"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "LAN"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Homelab CA"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Homelab Root CA"),
        ]
    )

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=825))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )

    # Dateien speichern
    with open(CA_KEY, "wb") as f:
        f.write(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    with open(CA_CERT, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    return templates.TemplateResponse(
        "form.html", {
            "request": request,
            "ca_created": True,
            "ca_exists": True,
            "key_types": KEY_TYPES,
        }
    )
