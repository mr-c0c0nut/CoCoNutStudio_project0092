# M.C.O — Mini Command Operator

M.C.O la mot terminal web nhe, chay bang Flask, cho phep chay mot tap lenh
duoc whitelist san de chan doan mang va he thong (ping, dns, http, headers,
cert, whois, hash, base64, thong tin server...). Khong co eval(), khong co
shell execution tuy y, khong chay ma nguon tu GitHub.

COCOTHON la ten goi/du an tong the ma M.C.O la thanh phan terminal chinh —
trong pham vi repo nay, COCOTHON va M.C.O duoc trien khai nhu cung mot ung
dung Flask duy nhat.

## Cau truc project

```
/
├── templates/
│   └── index.html
├── Procfile
├── README.md
├── app.py
├── data/
│   ├── example.json
│   └── example.txt
├── requirements.txt
└── runtime.txt
```

`data/` co the de trong neu ban khong can du lieu mau — cac lenh `json` va
`search` chi doc file nam trong thu muc nay.

## Vi du lenh

```
MCO > help
MCO > check ping google.com
MCO > check dns google.com
MCO > check headers example.com
MCO > check cert example.com
MCO > target 192.168.1.20
MCO > alias pc01 = 192.168.1.20
MCO > check ping pc01
MCO > hash sha256 "hello"
MCO > encode base64 "hello"
MCO > decode base64 "aGVsbG8="
MCO > run "user/project"
MCO > system
```

## Chay local

```bash
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

Mac dinh chay tai `http://localhost:5000`.

## Deploy len Render

1. Push toan bo project len mot GitHub repository.
2. Tren Render, tao **New Web Service**, tro toi repo do.
3. Build Command: `pip install -r requirements.txt`
4. Start Command: (Render se tu dung `Procfile`) `gunicorn app:app`
5. Them Environment Variable `MCO_SECRET_KEY` voi mot chuoi ngau nhien,
   dung cho Flask session (luu target/alias theo phien lam viec).
6. Deploy. Render se tu nhan `runtime.txt` de chon Python version.

## Gioi han bao mat (quan trong)

- Khong co lenh nao duoc chay qua `eval()`, `exec()`, hoac `os.system()`.
- Moi loi goi `subprocess` (chi dung cho `ping`) dung dang list argument,
  khong dung `shell=True`, va target da duoc kiem tra dinh dang truoc.
- `check ports` chi quet mot danh sach cong pho bien co gioi han, khong
  dung de quet dai IP hay Internet dien rong.
- Moi thao tac mang (ping/dns/http/headers/cert/whois) deu co timeout va
  gioi han do dai output.
- Lenh `json` va `search` chi duoc doc file nam trong thu muc `data/`,
  khong cho phep path traversal ra ngoai thu muc nay.
- `system`/`cpu`/`memory`/`disk`/`process`/`uptime` chi hien thi thong tin
  cua chinh moi truong chay app (qua `psutil`), khong cho phep nguoi dung
  chay lenh he thong tuy y.

## Gioi han cua RUN

`run "user/project"` **khong** thuc thi bat ky ma nguon nao tu GitHub.
Trong phien ban nay, no chi:

- Nhan dien va kiem tra dinh dang tham chieu repo (`user/project` hoac
  URL GitHub day du).
- Tra ve thong tin co ban cua repository (neu GitHub API cho phep truy cap
  cong khai).
- Bao trang thai `READY` cung thong bao ro rang:
  *"Execution sandbox is not enabled in this version."*

Khong co sandbox thuc thi ma nguon trong phien ban nay, va se khong duoc
them cho den khi co co che cach ly an toan (container/sandbox rieng).
