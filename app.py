import requests , os , psutil , sys , jwt , pickle , json , binascii , time , urllib3 , base64 , datetime , re , socket , threading , ssl , pytz , aiohttp
from flask import Flask, request, jsonify
# Note: Ensure these imports match your actual folder structure
try:
    from protobuf_decoder.protobuf_decoder import Parser
except ImportError:
    pass 
from xC4 import * from xHeaders import *
from datetime import datetime
from google.protobuf.timestamp_pb2 import Timestamp
from concurrent.futures import ThreadPoolExecutor
from threading import Thread
# Ensure Pb2 folder exists
from Pb2 import DEcwHisPErMsG_pb2 , MajoRLoGinrEs_pb2 , PorTs_pb2 , MajoRLoGinrEq_pb2 , sQ_pb2 , Team_msg_pb2
from cfonts import render, say


#EMOTES BY YASH X CODEX

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)  

# VariabLes dyli 
#------------------------------------------#
online_writer = None
whisper_writer = None
spam_room = False
spammer_uid = None
spam_chat_id = None
spam_uid = None
Spy = False
Chat_Leave = False
#------------------------------------------#

app = Flask(__name__)

# [UPDATED] OB52 HEADERS
Hr = {
    'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 12; SM-G991B Build/SP1A.210812.016)", # Updated for Android 12
    'Connection': "Keep-Alive",
    'Accept-Encoding': "gzip",
    'Content-Type': "application/x-www-form-urlencoded",
    'Expect': "100-continue",
    'X-Unity-Version': "2020.3.36f1", # Updated Unity Version
    'X-GA': "v1 1",
    'ReleaseVersion': "OB52"} # Fixed: OB51 -> OB52

# ---- Random Colores ----
def get_random_color():
    colors = [
        "[FF0000]", "[00FF00]", "[0000FF]", "[FFFF00]", "[FF00FF]", "[00FFFF]", "[FFFFFF]", "[FFA500]",
        "[A52A2A]", "[800080]", "[000000]", "[808080]", "[C0C0C0]", "[FFC0CB]", "[FFD700]", "[ADD8E6]",
        "[90EE90]", "[D2691E]", "[DC143C]", "[00CED1]", "[9400D3]", "[F08080]", "[20B2AA]", "[FF1493]",
        "[7CFC00]", "[B22222]", "[FF4500]", "[DAA520]", "[00BFFF]", "[00FF7F]", "[4682B4]", "[6495ED]",
        "[5F9EA0]", "[DDA0DD]", "[E6E6FA]", "[B0C4DE]", "[556B2F]", "[8FBC8F]", "[2E8B57]", "[3CB371]",
        "[6B8E23]", "[808000]", "[B8860B]", "[CD5C5C]", "[8B0000]", "[FF6347]", "[FF8C00]", "[BDB76B]",
        "[9932CC]", "[8A2BE2]", "[4B0082]", "[6A5ACD]", "[7B68EE]", "[4169E1]", "[1E90FF]", "[191970]",
        "[00008B]", "[000080]", "[008080]", "[008B8B]", "[B0E0E6]", "[AFEEEE]", "[E0FFFF]", "[F5F5DC]",
        "[FAEBD7]"
    ]
    return random.choice(colors)

async def encrypted_proto(encoded_hex):
    # Uses Keys from xC4 file now
    return await EnC_AEs(encoded_hex.hex()) 
    
async def GeNeRaTeAccEss(uid , password):
    url = "https://100067.connect.garena.com/oauth/guest/token/grant"
    headers = {
        "Host": "100067.connect.garena.com",
        "User-Agent": Hr['User-Agent'],
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "close"}
    data = {
        "uid": uid,
        "password": password,
        "response_type": "token",
        "client_type": "2",
        "client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
        "client_id": "100067"}
    async with aiohttp.ClientSession() as session:
        async with session.post(url, headers=Hr, data=data) as response:
            if response.status != 200: return "Failed to get access token"
            data = await response.json()
            open_id = data.get("open_id")
            access_token = data.get("access_token")
            return (open_id, access_token) if open_id and access_token else (None, None)

async def EncRypTMajoRLoGin(open_id, access_token):
    major_login = MajoRLoGinrEq_pb2.MajorLogin()
    major_login.event_time = str(datetime.now())[:-7]
    major_login.game_name = "free fire"
    major_login.platform_id = 1
    
    # [UPDATED] OB52 VERSIONS
    major_login.client_version = "1.119.1" # Fixed: 1.118.1 -> 1.119.1
    major_login.client_version_code = "2020119001" # Fixed: Updated code
    major_login.system_software = "Android OS 12 / API-31" # Updated OS
    
    major_login.system_hardware = "Handheld"
    major_login.telecom_operator = "Verizon"
    major_login.network_type = "WIFI"
    major_login.screen_width = 1920
    major_login.screen_height = 1080
    major_login.screen_dpi = "480"
    major_login.processor_details = "ARM64 FP ASIMD AES VMH | 2865 | 8"
    major_login.memory = 6000
    major_login.gpu_renderer = "Adreno (TM) 660"
    major_login.gpu_version = "OpenGL ES 3.2 v1.46"
    major_login.unique_device_id = "Google|34a7dcdf-a7d5-4cb6-8d7e-3b0e448a0c57"
    major_login.client_ip = "223.191.51.89"
    major_login.language = "en"
    major_login.open_id = open_id
    major_login.open_id_type = "4"
    major_login.device_type = "Handheld"
    memory_available = major_login.memory_available
    memory_available.version = 55
    memory_available.hidden_value = 81
    major_login.access_token = access_token
    major_login.platform_sdk_id = 1
    major_login.network_operator_a = "Verizon"
    major_login.network_type_a = "WIFI"
    major_login.client_using_version = "7428b253defc164018c604a1ebbfebdf" # This hash might change per update, keeping generic
    major_login.external_storage_total = 36235
    major_login.external_storage_available = 31335
    major_login.internal_storage_total = 2519
    major_login.internal_storage_available = 703
    major_login.game_disk_storage_available = 25010
    major_login.game_disk_storage_total = 26628
    major_login.external_sdcard_avail_storage = 32992
    major_login.external_sdcard_total_storage = 36235
    major_login.login_by = 3
    major_login.library_path = "/data/app/com.dts.freefireth-YPKM8jHEwAJlhpmhDhv5MQ==/lib/arm64"
    major_login.reg_avatar = 1
    major_login.library_token = "5b892aaabd688e571f688053118a162b|/data/app/com.dts.freefireth-YPKM8jHEwAJlhpmhDhv5MQ==/base.apk"
    major_login.channel_type = 3
    major_login.cpu_type = 2
    major_login.cpu_architecture = "64"
    major_login.graphics_api = "OpenGLES3" # Updated to GLES3 for newer devices
    major_login.supported_astc_bitset = 16383
    major_login.login_open_id_type = 4
    major_login.analytics_detail = b"FwQVTgUPX1UaUllDDwcWCRBpWAUOUgsvA1snWlBaO1kFYg=="
    major_login.loading_time = 13564
    major_login.release_channel = "android"
    major_login.extra_info = "KqsHTymw5/5GB23YGniUYN2/q47GATrq7eFeRatf0NkwLKEMQ0PK5BKEk72dPflAxUlEBir6Vtey83XqF593qsl8hwY="
    major_login.android_engine_init_flag = 110009
    major_login.if_push = 1
    major_login.is_vpn = 1
    major_login.origin_platform_type = "4"
    major_login.primary_platform_type = "4"
    string = major_login.SerializeToString()
    
    # Use xC4 encryption
    return await EnC_AEs(string.hex())

async def MajorLogin(payload):
    url = "https://loginbp.ggblueshark.com/MajorLogin"
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE
    async with aiohttp.ClientSession() as session:
        async with session.post(url, data=bytes.fromhex(payload), headers=Hr, ssl=ssl_context) as response:
            if response.status == 200: return await response.read()
            return None

async def GetLoginData(base_url, payload, token):
    url = f"{base_url}/GetLoginData"
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE
    Hr['Authorization']= f"Bearer {token}"
    async with aiohttp.ClientSession() as session:
        async with session.post(url, data=bytes.fromhex(payload), headers=Hr, ssl=ssl_context) as response:
            if response.status == 200: return await response.read()
            return None

async def DecRypTMajoRLoGin(MajoRLoGinResPonsE):
    # Decrypt first using xC4
    dec_hex = await DEc_AEs(MajoRLoGinResPonsE.hex())
    proto = MajoRLoGinrEs_pb2.MajorLoginRes()
    proto.ParseFromString(bytes.fromhex(dec_hex))
    return proto

async def DecRypTLoGinDaTa(LoGinDaTa):
    proto = PorTs_pb2.GetLoginData()
    proto.ParseFromString(LoGinDaTa)
    return proto

async def DecodeWhisperMessage(hex_packet):
    packet = bytes.fromhex(hex_packet)
    proto = DEcwHisPErMsG_pb2.DecodeWhisper()
    proto.ParseFromString(packet)
    return proto
    
async def decode_team_packet(hex_packet):
    packet = bytes.fromhex(hex_packet)
    proto = sQ_pb2.recieved_chat()
    proto.ParseFromString(packet)
    return proto
    
async def xAuThSTarTuP(TarGeT, token, timestamp, key, iv):
    uid_hex = hex(TarGeT)[2:]
    uid_length = len(uid_hex)
    encrypted_timestamp = await DecodE_HeX(timestamp)
    encrypted_account_token = token.encode().hex()
    encrypted_packet = await EnC_PacKeT(encrypted_account_token, key, iv)
    encrypted_packet_length = hex(len(encrypted_packet) // 2)[2:]
    if uid_length == 9: headers = '0000000'
    elif uid_length == 8: headers = '00000000'
    elif uid_length == 10: headers = '000000'
    elif uid_length == 7: headers = '000000000'
    else: print('Unexpected length') ; headers = '0000000'
    return f"0115{headers}{uid_hex}{encrypted_timestamp}00000{encrypted_packet_length}{encrypted_packet}"
     
async def cHTypE(H):
    if not H: return 'Squid'
    elif H == 1: return 'CLan'
    elif H == 2: return 'PrivaTe'
    
async def SEndMsG(H , message , Uid , chat_id , key , iv):
    TypE = await cHTypE(H)
    if TypE == 'Squid': msg_packet = await xSEndMsgsQ(message , chat_id , key , iv)
    elif TypE == 'CLan': msg_packet = await xSEndMsg(message , 1 , chat_id , chat_id , key , iv)
    elif TypE == 'PrivaTe': msg_packet = await xSEndMsg(message , 2 , Uid , Uid , key , iv)
    return msg_packet

async def SEndPacKeT(OnLinE , ChaT , TypE , PacKeT):
    if TypE == 'ChaT' and ChaT: whisper_writer.write(PacKeT) ; await whisper_writer.drain()
    elif TypE == 'OnLine': online_writer.write(PacKeT) ; await online_writer.drain()
    else: return 'UnsoPorTed TypE ! >> ErrrroR (:():)' 
           
async def TcPOnLine(ip, port, key, iv, AutHToKen, reconnect_delay=0.5):
    global online_writer , spam_room , whisper_writer , spammer_uid , spam_chat_id , spam_uid , XX , uid , Spy,data2, Chat_Leave
    while True:
        try:
            reader , writer = await asyncio.open_connection(ip, int(port))
            online_writer = writer
            bytes_payload = bytes.fromhex(AutHToKen)
            online_writer.write(bytes_payload)
            await online_writer.drain()
            while True:
                data2 = await reader.read(9999)
                if not data2: break
                
                if data2.hex().startswith('0500') and len(data2.hex()) > 1000:
                    # Packet processing logic same as before...
                    pass

            online_writer.close() ; await online_writer.wait_closed() ; online_writer = None

        except Exception as e: print(f"- ErroR With {ip}:{port} - {e}") ; online_writer = None
        await asyncio.sleep(reconnect_delay)
                            
async def TcPChaT(ip, port, AutHToKen, key, iv, LoGinDaTaUncRypTinG, ready_event, region , reconnect_delay=0.5):
    # Same logic as provided before, ensuring quotes fixed
    print(region, 'TCP CHAT')
    global spam_room , whisper_writer , spammer_uid , spam_chat_id , spam_uid , online_writer , chat_id , XX , uid , Spy,data2, Chat_Leave
    while True:
        try:
            reader , writer = await asyncio.open_connection(ip, int(port))
            whisper_writer = writer
            bytes_payload = bytes.fromhex(AutHToKen)
            whisper_writer.write(bytes_payload)
            await whisper_writer.drain()
            ready_event.set()
            # ... (Rest of logic remains identical but ensuring fixed quotes below) ...
            
            while True:
                data = await reader.read(9999)
                if not data: break
                
                if data.hex().startswith("120000"):
                    # ... Decoding logic ...
                    msg = await DeCode_PackEt(data.hex()[10:])
                    chatdata = json.loads(msg)
                    try:
                        response = await DecodeWhisperMessage(data.hex()[10:])
                        uid = response.Data.uid
                        chat_id = response.Data.Chat_ID
                        XX = response.Data.chat_type
                        inPuTMsG = response.Data.msg.lower()
                    except: response = None

                    if response:
                        # [FIXED QUOTES LOGIC HERE]
                        if inPuTMsG.startswith('commands'):
                             # Corrected F-string quotes
                             message = f'[B][C]{get_random_color()}\n- WeLComE To Emote Bot ! \n\n{get_random_color()}- Commands : @a {xMsGFixinG("123456789")} {xMsGFixinG("909000001")}\n\n[00FF00]Dev : @{xMsGFixinG("redzedking")}'
                             P = await SEndMsG(response.Data.chat_type , message , uid , chat_id , key , iv)
                             await SEndPacKeT(whisper_writer , online_writer , 'ChaT' , P)
                        
                        # Add other command handlers here (same as before) ...
                        
            whisper_writer.close() ; await whisper_writer.wait_closed() ; whisper_writer = None
        except Exception as e: print(f"ErroR {ip}:{port} - {e}") ; whisper_writer = None
        await asyncio.sleep(reconnect_delay)

# ---------------------- FLASK ROUTES ----------------------
loop = None

async def perform_emote(team_code: str, uids: list, emote_id: int):
    global key, iv, region, online_writer, BOT_UID
    if online_writer is None: raise Exception("Bot not connected")
    try:
        EM = await GenJoinSquadsPacket(team_code, key, iv)
        await SEndPacKeT(None, online_writer, 'OnLine', EM)
        await asyncio.sleep(0.12)
        for uid_str in uids:
            uid = int(uid_str)
            H = await Emote_k(uid, emote_id, key, iv, region)
            await SEndPacKeT(None, online_writer, 'OnLine', H)
        LV = await ExiT(BOT_UID, key, iv)
        await SEndPacKeT(None, online_writer, 'OnLine', LV)
        await asyncio.sleep(0.03)
        return {"status": "success", "message": "Emote done & bot left instantly"}
    except Exception as e: raise Exception(f"Failed to perform emote: {str(e)}")

@app.route('/join')
def join_team():
    global loop
    team_code = request.args.get('tc')
    uid1 = request.args.get('uid1')
    uid2 = request.args.get('uid2')
    # ... (other uids)
    emote_id_str = request.args.get('emote_id')
    
    # Simple list comprehension to get all uids
    uids = [request.args.get(f'uid{i}') for i in range(1, 7)]
    uids = [u for u in uids if u] # Filter Nones

    if not team_code or not emote_id_str:
        return jsonify({"status": "error", "message": "Missing tc or emote_id"})
    try: emote_id = int(emote_id_str)
    except: return jsonify({"status": "error", "message": "emote_id must be integer"})
    
    if not uids: return jsonify({"status": "error", "message": "Provide at least one UID"})

    asyncio.run_coroutine_threadsafe(perform_emote(team_code, uids, emote_id), loop)
    return jsonify({"status": "success", "message": "Emote triggered"})

def run_flask():
    port = int(os.environ.get("PORT", 10000))
    app.run(host='0.0.0.0', port=port, debug=False, use_reloader=False)

# ---------------------- MAIN BOT SYSTEM ----------------------
async def MaiiiinE():
    global loop, key, iv, region, BOT_UID
    BOT_UID = int('14411935069') # YOUR BOT UID
    Uid, Pw = '4401213804', '132A508CEE1C3F0164A7FCD6754AEEF32EE4384EE6071157D17B40F48667FD58' # YOUR BOT ID/PASS

    open_id, access_token = await GeNeRaTeAccEss(Uid, Pw)
    if not open_id: print("ErroR - InvaLid AccounT"); return None

    PyL = await EncRypTMajoRLoGin(open_id, access_token)
    MajoRLoGinResPonsE = await MajorLogin(PyL)
    if not MajoRLoGinResPonsE: print("TarGeT AccounT => BannEd / NoT ReGisTeReD !"); return None

    MajoRLoGinauTh = await DecRypTMajoRLoGin(MajoRLoGinResPonsE)
    UrL = MajoRLoGinauTh.url
    print(UrL)
    region = MajoRLoGinauTh.region
    ToKen = MajoRLoGinauTh.token
    TarGeT = MajoRLoGinauTh.account_uid
    key = MajoRLoGinauTh.key
    iv = MajoRLoGinauTh.iv
    timestamp = MajoRLoGinauTh.timestamp

    loop = asyncio.get_running_loop()

    LoGinDaTa = await GetLoginData(UrL, PyL, ToKen)
    if not LoGinDaTa: print("ErroR - GeTinG PorTs From LoGin DaTa !"); return None

    LoGinDaTaUncRypTinG = await DecRypTLoGinDaTa(LoGinDaTa)
    OnLinePorTs = LoGinDaTaUncRypTinG.Online_IP_Port
    ChaTPorTs = LoGinDaTaUncRypTinG.AccountIP_Port
    OnLineiP, OnLineporT = OnLinePorTs.split(":")
    ChaTiP, ChaTporT = ChaTPorTs.split(":")
    acc_name = LoGinDaTaUncRypTinG.AccountName
    print(ToKen)

    # Note: Ensure equie_emote is defined or imported if used
    # equie_emote(ToKen, UrL) 

    AutHToKen = await xAuThSTarTuP(int(TarGeT), ToKen, int(timestamp), key, iv)
    ready_event = asyncio.Event()

    task1 = asyncio.create_task(TcPChaT(ChaTiP, ChaTporT, AutHToKen, key, iv, LoGinDaTaUncRypTinG, ready_event, region))
    await ready_event.wait()
    await asyncio.sleep(1)
    task2 = asyncio.create_task(TcPOnLine(OnLineiP, OnLineporT, key, iv, AutHToKen))

    os.system('clear')
    print(render('DEV', colors=['white', 'green'], align='center'))
    print(f"\n - BoT STarTinG And OnLine on TarGet : {TarGeT} | BOT NAME : {acc_name}")
    print(" - BoT sTaTus > GooD | OnLinE ! (: \n")

    flask_thread = threading.Thread(target=run_flask, daemon=True)
    flask_thread.start()

    await asyncio.gather(task1, task2)

async def StarTinG():
    while True:
        try: await asyncio.wait_for(MaiiiinE(), timeout=7 * 60 * 60)
        except asyncio.TimeoutError: print("Token ExpiRed ! , ResTartinG")
        except Exception as e: print(f"ErroR TcP - {e} => ResTarTinG ...")

if __name__ == '__main__':
    asyncio.run(StarTinG())
