import os
from pathlib import Path
from datetime import datetime, timedelta, timezone
from fastapi import FastAPI, Form, Request
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


@app.get("/", response_class=HTMLResponse)
async def form(request: Request):
    ca_exists = CA_CERT.exists() and CA_KEY.exists()
    return templates.TemplateResponse(
        "form.html", {"request": request, "ca_exists": ca_exists}
    )

@app.post("/", response_class=HTMLResponse)
async def create_cert(
    request: Request,
    hostname: str = Form(...),
    alt_names: str = Form(""),
    cert_key_type: str = Form(...)
):
    ca_exists = CA_CERT.exists() and CA_KEY.exists()

    alt_names_list = [n.strip() for n in alt_names.split(",") if n.strip()]

    # Key je nach Auswahl erzeugen
    if cert_key_type == "rsa":
        key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    elif cert_key_type == "secp256r1":
        key = ec.generate_private_key(ec.SECP256R1())
    elif cert_key_type == "secp521r1":
        key = ec.generate_private_key(ec.SECP521R1())
    else:
        raise ValueError("Ungültiger Zertifikats-Key-Typ")

    # Rest bleibt unverändert …

    host_dir = FILE_DIR / hostname
    host_dir.mkdir(parents=True, exist_ok=True)

    # Schlüssel generieren
    key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    key_path = host_dir / f"{hostname}.key"
    with open(key_path, "wb") as f:
        f.write(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

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
    alt_names_objs = [x509.DNSName(hostname)] + [
        x509.DNSName(n) for n in alt_names_list
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
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=825))
        .add_extension(x509.SubjectAlternativeName(alt_names_objs), critical=False)
        .sign(private_key=ca_key, algorithm=hashes.SHA256())
    )

    cert_path = host_dir / f"{hostname}.crt"
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    cert_content = cert.public_bytes(serialization.Encoding.PEM).decode()
    key_content = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()

    key_path = host_dir / f"{hostname}.key"
    with open(key_path, "wb") as f:
        f.write(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    # Kombinierte PEM-Datei (Key + Zertifikat)
    combined_path = host_dir / f"{hostname}.pem"
    with open(combined_path, "wb") as f:
        f.write(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    # Ergebnis direkt unter dem Formular anzeigen
    return templates.TemplateResponse(
        "form.html",
        {
            "request": request,
            "hostname": hostname,
            "cert_content": cert_content,
            "key_content": key_content,
            "ca_exists": ca_exists,
        },
    )

@app.get("/download/{hostname}/{filename}")
async def download_file(hostname: str, filename: str):
    full_path = FILE_DIR / hostname / filename
    return FileResponse(full_path, filename=filename)

@app.get("/download-ca/{filename}")
async def download_ca(filename: str):
    if filename == "ca.key":
        return HTMLResponse("Der private CA-Schlüssel kann nicht heruntergeladen werden.", status_code=403)

    full_path = CERT_DIR / filename
    return FileResponse(full_path, filename=filename)

@app.post("/create-ca", response_class=HTMLResponse)
async def create_ca(request: Request, ca_key_type: str = Form(...)):
    CERT_DIR.mkdir(parents=True, exist_ok=True)

    # Key je nach Auswahl erzeugen
    if ca_key_type == "rsa":
        key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    elif ca_key_type == "secp256r1":
        key = ec.generate_private_key(ec.SECP256R1())
    elif ca_key_type == "secp521r1":
        key = ec.generate_private_key(ec.SECP521R1())
    else:
        raise ValueError("Ungültiger CA-Key-Typ")

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
        "form.html", {"request": request, "ca_created": True, "ca_exists": True}
    )
