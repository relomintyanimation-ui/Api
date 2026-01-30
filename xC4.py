import requests, json, binascii, time, urllib3, base64, datetime, re, socket, threading, random, os, asyncio
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# ---------------------------------------------------------
# [!] YAHAN ATTENTION DO [!]
# Ye KEYS tumhare Pb2 folder mein nahi hoti.
# Ye tumhe Internet/Telegram groups se 'OB52 AES KEY' ke naam se dhoondhni hongi.
# ---------------------------------------------------------
Key = b'YOUR_OB52_KEY_HERE'  # <--- Yahan 16 bytes ki key aayegi
Iv  = b'YOUR_OB52_IV_HERE'   # <--- Yahan 16 bytes ka IV aayega

async def EnC_AEs(HeX):
    # Agar Key galat hui to ye function crash karega
    try:
        cipher = AES.new(Key, AES.MODE_CBC, Iv)
        return cipher.encrypt(pad(bytes.fromhex(HeX), AES.block_size)).hex()
    except Exception as e:
        print(f"Encryption Error (Key Galat Hai?): {e}")
        return ""

async def DEc_AEs(HeX):
    try:
        cipher = AES.new(Key, AES.MODE_CBC, Iv)
        return unpad(cipher.decrypt(bytes.fromhex(HeX)), AES.block_size).hex()
    except: return ""

async def EnC_PacKeT(HeX, K, V): 
    return AES.new(K, AES.MODE_CBC, V).encrypt(pad(bytes.fromhex(HeX), 16)).hex()
    
async def DEc_PacKeT(HeX, K, V):
    return unpad(AES.new(K, AES.MODE_CBC, V).decrypt(bytes.fromhex(HeX)), 16).hex()  

async def EnC_Uid(H, Tp='Uid'):
    e, H = [], int(H)
    while H:
        e.append((H & 0x7F) | (0x80 if H > 0x7F else 0)); H >>= 7
    return bytes(e).hex()

async def EnC_Vr(N):
    H = []
    while True:
        BesTo = N & 0x7F; N >>= 7
        if N: BesTo |= 0x80
        H.append(BesTo)
        if not N: break
    return bytes(H)

async def CrEaTe_VarianT(field_number, value):
    return await EnC_Vr((field_number << 3) | 0) + await EnC_Vr(value)

async def CrEaTe_LenGTh(field_number, value):
    encoded_value = value.encode() if isinstance(value, str) else value
    return await EnC_Vr((field_number << 3) | 2) + await EnC_Vr(len(encoded_value)) + encoded_value

async def CrEaTe_ProTo(fields):
    packet = bytearray()
    for field, value in fields.items():
        if isinstance(value, dict):
            packet.extend(await CrEaTe_LenGTh(field, await CrEaTe_ProTo(value)))
        elif isinstance(value, int):
            packet.extend(await CrEaTe_VarianT(field, value))
        elif isinstance(value, str):
            packet.extend(await CrEaTe_LenGTh(field, value))
    return packet

async def DecodE_HeX(H):
    R = hex(H); F = str(R)[2:]
    return "0" + F if len(F) == 1 else F

async def GeneRaTePk(Pk, N, K, V):
    PkEnc = await EnC_PacKeT(Pk, K, V)
    _ = await DecodE_HeX(int(len(PkEnc) // 2))
    HeadEr = N + ("000000" if len(_) == 2 else "00000" if len(_) == 3 else "0000")
    return bytes.fromhex(HeadEr + _ + PkEnc)

async def HeartBeat(K, V):
    return await GeneRaTePk("080112020800", '0815', K, V)

# --- xC4.py ke sabse neeche ye paste karein ---

async def HeartBeat(K, V):
    # Ye packet server ko har 20 second mein signal bhejta hai
    # Packet ID: 0815 (Ping) | Data: 080112020800 (Empty/KeepAlive)
    return await GeneRaTePk("080112020800", '0815', K, V)

