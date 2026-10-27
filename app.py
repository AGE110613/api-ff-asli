from flask import Flask, request, jsonify
import hmac, hashlib, requests, string, random, json, codecs, base64, time
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

app = Flask(__name__)

# ══════════════════════════════════════════════════════════════════════════
# KONFIGURASI GARENA
# ══════════════════════════════════════════════════════════════════════════
HEX_KEY = bytes.fromhex("32656534343831396539623435393838343531343130363762323831363231383734643064356437616639643866376530306331653534373135623764316533")
AES_KEY = bytes([89,103,38,116,99,37,68,69,117,104,54,37,90,99,94,56])
AES_IV  = bytes([54,111,121,90,68,114,50,50,69,51,121,99,104,106,77,37])

def encode_f14(s):
    ks = [0x30,0x30,0x30,0x32,0x30,0x31,0x37,0x30,0x30,0x30,0x30,0x30,0x32,0x30,0x31,0x37,0x30,0x30,0x30,0x30,0x30,0x32,0x30,0x31,0x37,0x30,0x30,0x30,0x30,0x30,0x32,0x30]
    return bytes(ord(c) ^ ks[i % len(ks)] for i, c in enumerate(s))

FIELD_22 = bytes.fromhex("4747524501010100620200001052aa0d669c6a368f08338060d2ee0690053af84a41edcd3558556ec10f24f46c93ac64ca41a16732c46a2cb071246a79b8929032f9e1b6f4ef331bd53cabf29b09b97349a46e9863c0314e1a0d80819fef8aabf03876b3d037db354a7ccb5c1bce96411fb3753f6f50e44c69c4ed617fa30efb8ffc0517ff2f636739be1f304d999cfd6fd48bf69454199794c3dc88f55a4bdbd66534d5a061359cdfd1fb680cd37918df9fdb3cf7d80067b0a3506c90063cf62b2ccec11e23913a2fd7c4ef091331967bb518a5ad1e551146b90821be800883abadde39d6c80a5d798611466c748f075481806c5842ce45e6bd4e3368ec08fe2ec41ceb880cd86249eb71693f79f0bccf9e590c3fae12519fe08c7a1905d0927690109e0df28574bb14847225db1a59230e6662ed7730e15ff9a6c815cb41b420edeada735a4b03e181037c37c2c850257311df2f07b0a56e759372cbd0268e3f13a292ee4373e38ab5096e0342a5e0d7fec6da2bbc265d74baadd2b24ee4f74862f82c21d6694bac53f8ce80312a30068a6276a641c19b11d0305c6fe2f531ac7de578b29f543697f5c73663e6f23aa15277b6122dcd4d4171e38f9ac0b173f39c58416a16c5c1f4a35acd065ce78f449cf538a249339e763272d458e4ed86c976591a9c066b3a37111e44091eb6b5a795249f3e5145db022a6055f2cc675936391312f688f89627845df222a91156555225be36f9714a0ba50246d0f003bda3c9c1292ab73b4f79635ddd023218eda93a302d79e023404c14396544a930b98ed54771aca7fec10d095587685b473e81a9619764fad9256529dcd6e911f4f4629612287d4ee3ec5389f6ec4ec020b0e2aac017232a9197be9e46239ce690fe5d4872b2e98e651510c971667f3aca8b59f3e9d50e43")

def encode_varint(n):
    if n < 0: return b''
    out = bytearray()
    while True:
        b = n & 0x7F; n >>= 7
        if n: b |= 0x80
        out.append(b)
        if not n: break
    return bytes(out)

def build_proto(fields):
    parts = []
    for k, v in fields.items():
        if isinstance(v, dict):
            nested = build_proto(v)
            parts.append(encode_varint((k << 3) | 2) + encode_varint(len(nested)) + nested)
        elif isinstance(v, int):
            parts.append(encode_varint((k << 3) | 0) + encode_varint(v))
        elif isinstance(v, (str, bytes)):
            ev = v.encode() if isinstance(v, str) else v
            parts.append(encode_varint((k << 3) | 2) + encode_varint(len(ev)) + ev)
    return b''.join(parts)

def aes_encrypt(hex_data):
    return AES.new(AES_KEY, AES.MODE_CBC, AES_IV).encrypt(pad(bytes.fromhex(hex_data), AES.block_size))

def encrypt_api(plain_hex):
    return AES.new(AES_KEY, AES.MODE_CBC, AES_IV).encrypt(pad(bytes.fromhex(plain_hex), AES.block_size)).hex()

# ══════════════════════════════════════════════════════════════════════════
# LOGIKA INTI GENERATE AKUN
# ══════════════════════════════════════════════════════════════════════════
def generate_ff_account(name_prefix, region="ID"):
    try:
        rand_part = "".join(random.choices("0123456789ABCDEF", k=16))
        password = f"API_{rand_part}"
        
        # 1. Register
        url = "https://100067.connect.garena.com/api/v2/oauth/guest:register"
        payload = {"app_id": 100067, "client_type": 2, "password": password, "source": 2}
        body_json = json.dumps(payload, separators=(",", ":"))
        signature = hmac.new(HEX_KEY, body_json.encode("utf-8"), hashlib.sha256).hexdigest()
        headers = {"User-Agent": "GarenaMSDK/4.0.42(SM-A525F ;Android)", "Authorization": f"Signature {signature}", "Content-Type": "application/json; charset=utf-8"}
        
        resp = requests.post(url, data=body_json, headers=headers, timeout=10)
        if resp.status_code != 200: return None
        uid = resp.json()["data"]["uid"]

        # 2. Get Token
        url = "https://100067.connect.garena.com/oauth/guest/token/grant"
        body = {"uid": uid, "password": password, "response_type": "token", "client_type": "2", "client_secret": HEX_KEY, "client_id": "100067"}
        resp = requests.post(url, data=body, headers={"Content-Type": "application/x-www-form-urlencoded"}, timeout=10)
        if resp.status_code != 200: return None
        
        j = resp.json()
        open_id, access_token = j['open_id'], j["access_token"]
        
        # 3. Major Login (Dapet Account ID & JWT)
        open_id_b, access_token_b = open_id.encode(), access_token.encode()
        payload_dict = {
            3: datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'), 4: b'free fire', 5: 1, 7: "2.132.4",
            8: "Android OS 12", 9: b'Handheld', 10: "Telkomsel", 11: "WIFI", 12: 1280, 13: 720, 14: b'240', 15: "ARMv8", 16: 5951, 17: "Adreno", 18: "OpenGL ES 3.2", 19: f'Google|{random.randint(1000,9999)}', 20: f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}", 21: "en",
            22: open_id_b, 23: b'4', 24: b'Handheld', 25: "SM-A525F", 26: "en", 29: access_token_b, 30: 1, 41: "Telkomsel", 42: "WIFI", 57: b'1ac4b80ecf0478a44203bf8fac6120f5',
            60: 30000, 61: 30000, 62: 2519, 63: 243, 64: 32357, 65: 34308, 66: 32357, 67: 34308, 73: 1,
            74: b'/data/app/arm', 76: 2, 77: b'428775ab8c8845bd341b5357ec61d15e|/data/app/base.apk', 78: 2, 79: 1, 81: b'32', 83: b'2019118525', 85: 3, 86: b'OpenGLES3', 87: 4095, 88: 4, 92: 19788, 93: b'android_max',
            94: b'KqsHT2gyPt7vUCc9SCjv2ioi3WEZSEL86ErvXB38suVVK', 96: b'{"cur_rate":null,"support_etc2":true}', 97: 1, 98: 1, 99: b'4', 100: b'4', 102: b'', 104: 77149, 105: 1,
            106: b'https://dl.cdn.freefiremobile.com/live/ABHotUpdates/', 107: b'c8e41b7a93f02d56e1a94c7b8203f5d1',
        }
        headers = {'Host': 'loginbp.ppmainecoonghj.com', 'User-Agent': 'UnityPlayer/2018.4.12f1', 'Accept': '*/*', 'Accept-Encoding': 'deflate, gzip', 'Authorization': 'Bearer', 'X-GA': 'v1 1', 'X-Ga-Sv': '1789534056', 'ReleaseVersion': "OB55", 'Content-Type': 'application/x-www-form-urlencoded', 'X-Unity-Version': '2018.4.12f1'}
        
        resp = requests.post("https://loginbp.ppmainecoonghj.com/MajorLogin", headers=headers, data=bytes.fromhex(encrypt_api(build_proto(payload_dict).hex())), timeout=10)
        
        jwt_token, account_id = "", "N/A"
        if resp.status_code == 200 and len(resp.text) > 10:
            jwt_start = resp.text.find("eyJ")
            if jwt_start != -1:
                jwt_token = resp.text[jwt_start:]
                second_dot = jwt_token.find(".", jwt_token.find(".") + 1)
                if second_dot != -1:
                    jwt_token = jwt_token[:second_dot + 44]
                    try:
                        parts = jwt_token.split('.')
                        if len(parts) >= 2:
                            pp = parts[1]; padding = 4 - len(pp) % 4
                            if padding != 4: pp += '=' * padding
                            claims = json.loads(base64.urlsafe_b64decode(pp))
                            account_id = claims.get('account_id') or claims.get('external_id')
                    except: pass

        # 4. Balikin Response
        return {
            "uid": str(uid),
            "password": password,
            "account_id": str(account_id),
            "name": f"{name_prefix}{random.randint(1000,9999)}",
            "region": region.upper(),
            "jwt_token": jwt_token
        }
    except Exception as e:
        return None

# ══════════════════════════════════════════════════════════════════════════
# API ENDPOINT (TAMPILAN WEB)
# ══════════════════════════════════════════════════════════════════════════
@app.route('/')
def home():
    return jsonify({
        "status": "ONLINE",
        "message": "Aurellia FF API - REAL ACCOUNT",
        "endpoint": "/api/gen?count=1&name=AGE&region=ID"
    })

@app.route('/api/gen')
def generate():
    count = int(request.args.get('count', 1))
    name = request.args.get('name', 'AGE')
    region = request.args.get('region', 'ID')
    
    # Batasi maksimal 10 akun per request biar ga kena rate limit
    count = min(count, 10) 
    
    accounts = []
    for i in range(count):
        akun = generate_ff_account(name, region)
        if akun:
            accounts.append(akun)
            
    return jsonify({
        "status": "success",
        "total": len(accounts),
        "data": accounts
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
