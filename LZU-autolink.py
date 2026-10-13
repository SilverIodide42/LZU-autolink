# -*- coding: utf-8 -*-
"""
================================================================================
           兰州大学校园网 (LZU) 自动检测与静默登录主程序 (All-in-One 单文件版)
================================================================================
 功能概述:
   1. 兰州大学深澜 Srun 4000 协议全功能认证 (@eLearning 认证 / 域后缀 @study)
   2. 后台持续监听网络连接状态，断线重连/需要认证时自动静默登录，0 窗口弹窗
   3. 全功能交互式 CLI 控制面板 (账号配置、网络探测、一键测试、服务启停、自启管理)
   4. Windows DPAPI (CryptProtectData) 本地高强度密码加密保存
   5. Windows 开机自启动全自动管理 (写入 Startup 文件夹及注册表 Run 项)
   6. 后台守护进程无窗口静默常驻与管控 (启动 / 停止 / 重启 / 运行状态监控)
   7. 自动日志滚动与实时日志查看
================================================================================
"""

import os
import sys
import time
import json
import base64
import ctypes
from ctypes import wintypes
import hmac
import hashlib
import math
import re
import unicodedata
import urllib.request
import urllib.parse
import winreg
import logging
from logging.handlers import RotatingFileHandler
import argparse
import getpass
import subprocess

# 解决 Windows 控制台编码问题与底层鼠标/QuickEdit模式初始化
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

    try:
        # 在模块加载之初立即关闭 QuickEdit (0x0040) 并开启鼠标与VT输入，避免控制台被挂起冻结
        kernel32 = ctypes.windll.kernel32
        GENERIC_READ = 0x80000000
        GENERIC_WRITE = 0x40000000
        h_conin = kernel32.CreateFileW("CONIN$", GENERIC_READ | GENERIC_WRITE, 3, None, 3, 0, None)
        h_conout = kernel32.CreateFileW("CONOUT$", GENERIC_READ | GENERIC_WRITE, 3, None, 3, 0, None)
        mode_in = wintypes.DWORD()
        mode_out = wintypes.DWORD()
        if kernel32.GetConsoleMode(h_conin, ctypes.byref(mode_in)):
            new_in = (mode_in.value & ~0x0040) | 0x0080 | 0x0010 | 0x0008 | 0x0200
            kernel32.SetConsoleMode(h_conin, new_in)
        if kernel32.GetConsoleMode(h_conout, ctypes.byref(mode_out)):
            kernel32.SetConsoleMode(h_conout, mode_out.value | 0x0004 | 0x0001)
    except Exception:
        pass

if getattr(sys, "frozen", False):
    SCRIPT_DIR = os.path.dirname(os.path.abspath(sys.executable))
else:
    SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = os.path.join(SCRIPT_DIR, "config.json")
LOG_FILE = os.path.join(SCRIPT_DIR, "LZU-autolink.log")
PID_FILE = os.path.join(SCRIPT_DIR, "daemon.pid")

# 深澜 Srun 4000 定制 Base64 码表
ALPHA = "LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA"
PADCHAR = "="

# ==================== 日志系统 ====================
def setup_logger():
    logger = logging.getLogger("LZU_Login")
    logger.setLevel(logging.INFO)
    if not logger.handlers:
        file_handler = RotatingFileHandler(
            LOG_FILE, maxBytes=2 * 1024 * 1024, backupCount=2, encoding="utf-8"
        )
        formatter = logging.Formatter("[%(asctime)s] [%(levelname)s] %(message)s", "%Y-%m-%d %H:%M:%S")
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    return logger

logger = setup_logger()

# ==================== DPAPI 密码加密 ====================
class DATA_BLOB(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_byte))]

def encrypt_password(password: str) -> str:
    """使用 Windows DPAPI 加密密码，与当前 Windows 用户深度绑定"""
    try:
        crypt32 = ctypes.windll.crypt32
        data_bytes = password.encode("utf-8")
        blob_in = DATA_BLOB(len(data_bytes), ctypes.cast(ctypes.create_string_buffer(data_bytes), ctypes.POINTER(ctypes.c_byte)))
        blob_out = DATA_BLOB()
        if crypt32.CryptProtectData(ctypes.byref(blob_in), "lzu_portal_pwd", None, None, None, 0, ctypes.byref(blob_out)):
            res = ctypes.string_at(blob_out.pbData, blob_out.cbData)
            ctypes.windll.kernel32.LocalFree(blob_out.pbData)
            return "dpapi:" + base64.b64encode(res).decode("utf-8")
    except Exception:
        pass
    return "b64:" + base64.b64encode(password.encode("utf-8")).decode("utf-8")

def decrypt_password(cipher_text: str) -> str:
    """使用 Windows DPAPI 解密密码"""
    if not cipher_text:
        return ""
    if cipher_text.startswith("dpapi:"):
        try:
            raw_bytes = base64.b64decode(cipher_text[6:])
            crypt32 = ctypes.windll.crypt32
            blob_in = DATA_BLOB(len(raw_bytes), ctypes.cast(ctypes.create_string_buffer(raw_bytes), ctypes.POINTER(ctypes.c_byte)))
            blob_out = DATA_BLOB()
            if crypt32.CryptUnprotectData(ctypes.byref(blob_in), None, None, None, None, 0, ctypes.byref(blob_out)):
                res = ctypes.string_at(blob_out.pbData, blob_out.cbData)
                ctypes.windll.kernel32.LocalFree(blob_out.pbData)
                return res.decode("utf-8")
        except Exception:
            return ""
    elif cipher_text.startswith("b64:"):
        try:
            return base64.b64decode(cipher_text[4:]).decode("utf-8")
        except Exception:
            return ""
    return cipher_text

# ==================== 配置管理 ====================
class ConfigManager:
    @staticmethod
    def load():
        default_config = {
            "username": "",
            "password_encrypted": "",
            "domain": "@study",  # @study 对应前端下拉框中的 @eLearning
            "host": "10.10.0.166",
            "acid": "2",
            "check_interval": 10
        }
        if os.path.exists(CONFIG_FILE):
            try:
                with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    default_config.update(data)
            except Exception as e:
                logger.error(f"读取配置文件失败: {e}")
        return default_config

    @staticmethod
    def save(config):
        try:
            with open(CONFIG_FILE, "w", encoding="utf-8") as f:
                json.dump(config, f, ensure_ascii=False, indent=2)
            return True
        except Exception as e:
            logger.error(f"保存配置文件失败: {e}")
            return False

# ==================== 开机自启动全内置管理 ====================
class AutoStartManager:
    REG_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
    APP_NAME = "LZU-autolink"
    STARTUP_DIR = os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup")
    STARTUP_VBS = os.path.join(STARTUP_DIR, "LZU-autolink.vbs")

    @classmethod
    def get_pythonw_path(cls):
        # 优先使用 pythonw.exe 实现完全隐藏窗口
        py_dir = os.path.dirname(sys.executable)
        pythonw_path = os.path.join(py_dir, "pythonw.exe")
        if os.path.exists(pythonw_path):
            return pythonw_path
        return sys.executable

    @classmethod
    def get_daemon_cmd(cls):
        # 判断自身是否为打包后的可执行文件或者脚本
        if getattr(sys, "frozen", False):
            return f'"{sys.executable}" --daemon'
        pythonw = cls.get_pythonw_path()
        script_file = os.path.abspath(__file__)
        return f'"{pythonw}" "{script_file}" --daemon'

    @classmethod
    def is_enabled(cls) -> bool:
        # 1. 检查 Startup 文件夹的 VBS
        if os.path.exists(cls.STARTUP_VBS):
            return True
        # 2. 检查注册表 Run 项
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, cls.REG_KEY, 0, winreg.KEY_READ)
            val, _ = winreg.QueryValueEx(key, cls.APP_NAME)
            winreg.CloseKey(key)
            if val:
                return True
        except Exception:
            pass
        return False

    @classmethod
    def set_autostart(cls, enable: bool) -> tuple[bool, str]:
        cmd = cls.get_daemon_cmd()
        if enable:
            # 方案 A: 写入 Windows 启动文件夹 VBScript (真正的后台无黑框静默运行)
            vbs_code = 'Set ws = CreateObject("WScript.Shell")\r\nws.Run """' + cmd.replace('"', '""') + '""", 0, False\r\n'
            vbs_ok = False
            try:
                os.makedirs(cls.STARTUP_DIR, exist_ok=True)
                with open(cls.STARTUP_VBS, "w", encoding="utf-8") as f:
                    f.write(vbs_code)
                vbs_ok = True
            except Exception as e_vbs:
                logger.warning(f"写入 Startup VBS 失败: {e_vbs}")

            # 方案 B: 尝试写入注册表 Run
            reg_ok = False
            try:
                key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, cls.REG_KEY, 0, winreg.KEY_SET_VALUE)
                winreg.SetValueEx(key, cls.APP_NAME, 0, winreg.REG_SZ, cmd)
                winreg.CloseKey(key)
                reg_ok = True
            except Exception as e_reg:
                logger.warning(f"写入注册表失败: {e_reg}")

            if vbs_ok or reg_ok:
                logger.info("开机自启动设置成功")
                return True, "已成功开启开机自启动！(电脑重启后将自动在后台静默运行)"
            else:
                return False, "未能写入开机自启动项，请检查系统文件夹或注册表权限。"
        else:
            cleaned = False
            # 清理 Startup 文件夹
            if os.path.exists(cls.STARTUP_VBS):
                try:
                    os.remove(cls.STARTUP_VBS)
                    cleaned = True
                except Exception as e:
                    # 容错: 若无法直接删除文件，尝试清空脚本内容使其无害失效
                    try:
                        with open(cls.STARTUP_VBS, "w", encoding="utf-8") as f:
                            f.write("' disabled\r\n")
                        cleaned = True
                    except Exception:
                        pass
                    logger.warning(f"清理 Startup VBS 失败: {e}")
            # 清理注册表
            try:
                key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, cls.REG_KEY, 0, winreg.KEY_SET_VALUE)
                winreg.DeleteValue(key, cls.APP_NAME)
                winreg.CloseKey(key)
                cleaned = True
            except Exception:
                pass

            if cleaned:
                logger.info("开机自启动已取消")
                return True, "已成功关闭开机自启动！"
            return False, "未能完全清理自启项，请检查权限。"

# ==================== 深澜 Srun 加解密算法 ====================
def srun_base64_encode(s: str) -> str:
    res = []
    imax = len(s) - len(s) % 3
    i = 0
    while i < imax:
        b10 = (ord(s[i]) << 16) | (ord(s[i+1]) << 8) | ord(s[i+2])
        res.append(ALPHA[b10 >> 18])
        res.append(ALPHA[(b10 >> 12) & 63])
        res.append(ALPHA[(b10 >> 6) & 63])
        res.append(ALPHA[b10 & 63])
        i += 3
    rem = len(s) - imax
    if rem == 1:
        b10 = ord(s[i]) << 16
        res.append(ALPHA[b10 >> 18] + ALPHA[(b10 >> 12) & 63] + PADCHAR + PADCHAR)
    elif rem == 2:
        b10 = (ord(s[i]) << 16) | (ord(s[i+1]) << 8)
        res.append(ALPHA[b10 >> 18] + ALPHA[(b10 >> 12) & 63] + ALPHA[(b10 >> 6) & 63] + PADCHAR)
    return "".join(res)

def _s(a: str, b: bool):
    c = len(a)
    v = []
    for i in range(0, c, 4):
        val = ord(a[i])
        if i + 1 < c: val |= ord(a[i + 1]) << 8
        if i + 2 < c: val |= ord(a[i + 2]) << 16
        if i + 3 < c: val |= ord(a[i + 3]) << 24
        v.append(val)
    if b:
        v.append(c)
    return v

def _l(a: list, b: bool):
    d = len(a)
    c = (d - 1) << 2
    if b:
        m = a[d - 1]
        if m < c - 3 or m > c:
            return None
        c = m
    chars = []
    for i in range(d):
        chars.append(chr(a[i] & 0xFF))
        chars.append(chr((a[i] >> 8) & 0xFF))
        chars.append(chr((a[i] >> 16) & 0xFF))
        chars.append(chr((a[i] >> 24) & 0xFF))
    s_val = "".join(chars)
    return s_val[:c] if b else s_val

def x_encode(msg: str, key: str) -> str:
    if not msg:
        return ""
    v = _s(msg, True)
    k = _s(key, False)
    if len(k) < 4:
        k.extend([0] * (4 - len(k)))
    n = len(v) - 1
    z = v[n]
    y = v[0]
    c = 0x86014019 | 0x183639A0
    q = math.floor(6 + 52 / (n + 1))
    d = 0
    while q > 0:
        q -= 1
        d = (d + c) & (0x8CE0D9BF | 0x731F2640)
        e = (d >> 2) & 3
        for p in range(n):
            y = v[p + 1]
            m = ((z >> 5) ^ (y << 2)) & 0xFFFFFFFF
            m = (m + (((y >> 3) ^ (z << 4)) ^ (d ^ y))) & 0xFFFFFFFF
            m = (m + (k[(p & 3) ^ e] ^ z)) & 0xFFFFFFFF
            v[p] = (v[p] + m) & (0xEFB8D130 | 0x10472ECF)
            z = v[p]
        y = v[0]
        m = ((z >> 5) ^ (y << 2)) & 0xFFFFFFFF
        m = (m + (((y >> 3) ^ (z << 4)) ^ (d ^ y))) & 0xFFFFFFFF
        m = (m + (k[(n & 3) ^ e] ^ z)) & 0xFFFFFFFF
        v[n] = (v[n] + m) & (0xBB390742 | 0x44C6F8BD)
        z = v[n]
    return _l(v, False)

# ==================== 深澜 Srun 客户端 ====================
class LzuSrunClient:
    def __init__(self, host="10.10.0.166", acid="2"):
        self.host = host
        self.acid = acid
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Referer": f"http://{host}/srun_portal_pc?ac_id={acid}&theme=pro"
        }

    def get_rad_user_info(self, timeout=2):
        """查询用户在线状态"""
        cb = f"jQuery{int(time.time()*1000)}"
        url = f"http://{self.host}/cgi-bin/rad_user_info?callback={cb}&_={int(time.time()*1000)}"
        req = urllib.request.Request(url, headers=self.headers)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                text = resp.read().decode("utf-8", errors="ignore")
                m = re.search(r"jQuery\d+\((.*)\)", text)
                if m:
                    return json.loads(m.group(1))
        except Exception as e:
            return {"error": "unreachable", "exception": str(e)}
        return {"error": "unknown"}

    def get_challenge(self, username: str, ip: str = "", timeout=3):
        """获取挑战 Token"""
        cb = f"jQuery{int(time.time()*1000)}"
        params = {
            "callback": cb,
            "username": username,
            "ip": ip,
            "_": int(time.time()*1000)
        }
        url = f"http://{self.host}/cgi-bin/get_challenge?" + urllib.parse.urlencode(params)
        req = urllib.request.Request(url, headers=self.headers)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            text = resp.read().decode("utf-8", errors="ignore")
            m = re.search(r"jQuery\d+\((.*)\)", text)
            if m:
                return json.loads(m.group(1))
        raise RuntimeError("网关未返回有效的 challenge 令牌")

    def login(self, username: str, password: str, domain: str = "@study", timeout=5):
        """执行后台静默认证登录 (支持 @eLearning 与 @lzu.edu.cn)"""
        full_username = username
        if "@" in username:
            full_username = username
        elif domain == "@study":
            full_username = f"{username}@study"
        elif domain == "@lzu.edu.cn":
            full_username = f"{username}@lzu.edu.cn"
        elif domain:
            full_username = f"{username}{domain}"

        # 检查当前在线状态
        user_info = self.get_rad_user_info(timeout=timeout)
        if user_info.get("error") == "ok":
            return {
                "success": True,
                "msg": f"当前设备已在线 (用户: {user_info.get('user_name')}, IP: {user_info.get('online_ip')})",
                "already_online": True,
                "data": user_info
            }
        
        client_ip = user_info.get("client_ip") or user_info.get("online_ip") or ""

        # 获取 challenge
        chal_res = self.get_challenge(full_username, client_ip, timeout=timeout)
        token = chal_res.get("challenge")
        if not token:
            return {"success": False, "msg": f"获取Challenge失败: {chal_res}"}
        
        if not client_ip:
            client_ip = chal_res.get("client_ip") or chal_res.get("online_ip") or ""

        # 构造加密数据
        hmd5 = hmac.new(token.encode("utf-8"), password.encode("utf-8"), hashlib.md5).hexdigest()
        info_dict = {
            "username": full_username,
            "password": password,
            "ip": client_ip,
            "acid": str(self.acid),
            "enc_ver": "srun_bx1"
        }
        info_json = json.dumps(info_dict, separators=(",", ":"))
        i = "{SRBX1}" + srun_base64_encode(x_encode(info_json, token))

        chkstr = token + full_username
        chkstr += token + hmd5
        chkstr += token + str(self.acid)
        chkstr += token + str(client_ip)
        chkstr += token + "200"
        chkstr += token + "1"
        chkstr += token + i
        chksum = hashlib.sha1(chkstr.encode("utf-8")).hexdigest()

        # 发起登录请求
        cb = f"jQuery{int(time.time()*1000)}"
        params = {
            "callback": cb,
            "action": "login",
            "username": full_username,
            "password": "{MD5}" + hmd5,
            "ac_id": str(self.acid),
            "ip": client_ip,
            "chksum": chksum,
            "info": i,
            "n": "200",
            "type": "1",
            "os": "Windows 10",
            "name": "Windows",
            "double_stack": "0",
            "_": int(time.time()*1000)
        }
        login_url = f"http://{self.host}/cgi-bin/srun_portal?" + urllib.parse.urlencode(params)
        req = urllib.request.Request(login_url, headers=self.headers)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            resp_text = resp.read().decode("utf-8", errors="ignore")
            m = re.search(r"jQuery\d+\((.*)\)", resp_text)
            if m:
                res = json.loads(m.group(1))
                res_code = res.get("res")
                error = res.get("error")
                error_msg = res.get("error_msg", "")
                suc_msg = res.get("suc_msg", "")

                if res_code == "ok" or error == "ok":
                    return {"success": True, "msg": f"登录成功！IP: {client_ip}", "data": res}
                elif error == "ip_already_online_error" or suc_msg == "ip_already_online_error":
                    return {"success": True, "msg": f"当前IP已在线 ({client_ip})", "already_online": True, "data": res}
                else:
                    return {"success": False, "msg": f"登录失败: {error_msg or error or res}", "data": res}
            else:
                return {"success": False, "msg": f"网关返回异常内容: {resp_text[:100]}"}

# ==================== 网络状态探测 ====================
def check_internet(timeout=2.0) -> bool:
    """探测外网连通性 (轻量 204 检测)"""
    test_urls = [
        "http://connect.rom.miui.com/generate_204",
        "http://connectivitycheck.gstatic.com/generate_204",
        "http://www.msftconnecttest.com/connecttest.txt"
    ]
    for url in test_urls:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                if resp.status == 204 or (resp.status == 200 and "Microsoft" in resp.read().decode("utf-8", errors="ignore")):
                    return True
        except Exception:
            continue
    return False

def is_lzu_gateway_reachable(host="10.10.0.166", timeout=2.0) -> bool:
    """检测兰大校园网认证网关是否可达"""
    try:
        req = urllib.request.Request(f"http://{host}/", headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status == 200
    except Exception:
        return False

# ==================== 后台进程管理 ====================
def is_pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    SYNCHRONIZE = 0x00100000
    h_process = ctypes.windll.kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, False, pid)
    if h_process:
        exit_code = ctypes.c_ulong()
        ctypes.windll.kernel32.GetExitCodeProcess(h_process, ctypes.byref(exit_code))
        ctypes.windll.kernel32.CloseHandle(h_process)
        return exit_code.value == 259  # STILL_ACTIVE
    return False

def get_daemon_pid() -> int | None:
    if os.path.exists(PID_FILE):
        try:
            with open(PID_FILE, "r", encoding="utf-8") as f:
                pid = int(f.read().strip())
                if is_pid_alive(pid):
                    return pid
        except Exception:
            pass
    return None

def start_daemon_process():
    """以静默无窗口模式启动后台守护进程"""
    pid = get_daemon_pid()
    if pid:
        return False, f"后台守护服务已在运行 (PID: {pid})"

    # 构建启动命令
    if getattr(sys, "frozen", False):
        cmd = [sys.executable, "--daemon"]
    else:
        pythonw_path = AutoStartManager.get_pythonw_path()
        cmd = [pythonw_path, os.path.abspath(__file__), "--daemon"]

    # Windows 完全隐藏窗口标志
    CREATE_NO_WINDOW = 0x08000000
    DETACHED_PROCESS = 0x00000008
    try:
        proc = subprocess.Popen(cmd, creationflags=CREATE_NO_WINDOW | DETACHED_PROCESS, close_fds=True)
        with open(PID_FILE, "w", encoding="utf-8") as f:
            f.write(str(proc.pid))
        logger.info(f"后台守护服务启动成功 (PID: {proc.pid})")
        return True, f"后台守护服务已成功启动！(PID: {proc.pid})"
    except Exception as e:
        logger.error(f"启动守护进程失败: {e}")
        return False, f"启动失败: {e}"

def stop_daemon_process():
    """停止后台守护进程"""
    pid = get_daemon_pid()
    if not pid:
        if os.path.exists(PID_FILE):
            os.remove(PID_FILE)
        return False, "后台守护进程未在运行"
    
    try:
        subprocess.run(["taskkill", "/F", "/PID", str(pid)], capture_output=True)
        if os.path.exists(PID_FILE):
            os.remove(PID_FILE)
        logger.info(f"后台守护服务已停止 (PID: {pid})")
        return True, f"已成功停止守护服务 (PID: {pid})"
    except Exception as e:
        logger.error(f"停止守护进程失败: {e}")
        return False, f"停止失败: {e}"

# ==================== 后台守护核心循环 ====================
def run_daemon_loop():
    """后台长期运行的网络监听循环"""
    my_pid = os.getpid()
    with open(PID_FILE, "w", encoding="utf-8") as f:
        f.write(str(my_pid))
    
    logger.info(f"=== LZU 校园网守护进程启动 (PID: {my_pid}) ===")

    fail_count = 0
    while True:
        try:
            config = ConfigManager.load()
            interval = int(config.get("check_interval", 10))
            username = config.get("username", "")
            encrypted_pwd = config.get("password_encrypted", "")
            password = decrypt_password(encrypted_pwd)
            domain = config.get("domain", "@study")
            host = config.get("host", "10.10.0.166")
            acid = config.get("acid", "2")

            # 1. 检查互联网连接
            has_internet = check_internet(timeout=2.0)
            if has_internet:
                fail_count = 0
                time.sleep(interval)
                continue

            # 2. 外网不通，检查是否在兰大内网环境
            if is_lzu_gateway_reachable(host=host, timeout=2.0):
                client = LzuSrunClient(host=host, acid=acid)
                info = client.get_rad_user_info(timeout=2.0)
                
                # 检查深澜在线状态
                if info.get("error") == "not_online_error" or not info.get("user_name"):
                    logger.info("检测到已连接 LZU 网络且处于未认证状态，准备执行静默登录...")
                    if not username or not password:
                        logger.warning("未配置有效的上网账号或密码，请先运行程序进行配置！")
                        time.sleep(30)
                        continue

                    # 执行认证登录
                    res = client.login(username=username, password=password, domain=domain)
                    if res.get("success"):
                        logger.info(f"静默登录成功！详情: {res.get('msg')}")
                        fail_count = 0
                        time.sleep(interval)
                    else:
                        logger.error(f"静默登录失败: {res.get('msg')}")
                        fail_count += 1
                        # 失败后增加等待时间，防止频繁重试被封禁
                        sleep_time = min(30 * fail_count, 120)
                        time.sleep(sleep_time)
                else:
                    # 设备在深澜系统中显示已在线，但外网尚未联通
                    time.sleep(interval)
            else:
                # 兰大网关不可达（未连接 LZU WiFi 或有线网）
                time.sleep(interval)

        except Exception as e:
            logger.error(f"守护循环异常: {e}")
            time.sleep(10)

# ==================== CLI极速键盘事件监听 ====================
def get_menu_key():
    """
    纯键盘毫秒级无延迟交互监听:
    - ↑ / ↓ 方向键: 仅由专业方向键控制移动
    - Enter / 空格: 确认选中当前菜单项
    - 1 ~ 7 / 0: 单键秒级直达触发 (无需按回车)
    - Backspace / Delete / ESC / q: 返回或退出
    """
    import msvcrt
    while True:
        if msvcrt.kbhit():
            ch = msvcrt.getwch()

            # 1. 回车 / 空格 确认
            if ch in ['\r', '\n', ' ']:
                return 'ENTER'

            # 2. Backspace (删除键) 返回上一级
            elif ch in ['\x08', '\x7f']:
                return 'ESC'

            # 3. ANSI 转义序列处理 (VT 模式下方向键为 \x1b[A / \x1b[B, Delete 为 \x1b[3~)
            elif ch == '\x1b':
                seq = ch
                t0 = time.time()
                while time.time() - t0 < 0.05:
                    if msvcrt.kbhit():
                        seq += msvcrt.getwch()
                        if seq.endswith(('A', 'B', 'C', 'D', '~')):
                            break
                    else:
                        time.sleep(0.003)

                if seq in ['\x1b[A', '\x1bOA']:
                    return 'UP'
                elif seq in ['\x1b[B', '\x1bOB']:
                    return 'DOWN'
                elif seq in ['\x1b[C', '\x1bOC']:
                    return 'ENTER'
                elif seq in ['\x1b[3~']:
                    return 'ESC'  # Delete 键
                elif seq == '\x1b':
                    return 'ESC'

            # 4. Win32 扩展扫描码 (传统 CMD 下方向键为 \xe0 或 \x00 + H/P, Delete 为 S)
            elif ch in ['\xe0', '\x00']:
                code = msvcrt.getwch()
                if code == 'H':
                    return 'UP'
                elif code == 'P':
                    return 'DOWN'
                elif code == 'S':  # Delete 键扫描码
                    return 'ESC'

            # 5. 单键秒选数字键
            elif ch in '01234567':
                return ch

            # 6. 快捷退出
            elif ch.lower() in ['q', 'x']:
                return 'ESC'
        else:
            time.sleep(0.015)

def wait_for_return():
    """等待用户按 Backspace (删除键)、Delete、回车或 ESC 返回上一级主菜单"""
    import msvcrt
    T = ClaudeTheme
    sys.stdout.write(f"\n  {T.DIM}按 {T.ORANGE}Backspace (删除键){T.DIM} 或 {T.ORANGE}回车键{T.DIM} 返回上一级菜单...{T.RESET}\n")
    sys.stdout.flush()

    while True:
        if msvcrt.kbhit():
            ch = msvcrt.getwch()
            if ch in ['\x08', '\x7f', '\r', '\n', ' ', '\x1b']:
                break
            elif ch in ['\xe0', '\x00']:
                code = msvcrt.getwch()
                if code in ['S', 'H', 'P']:
                    break
        else:
            time.sleep(0.015)

# ==================== CLI视觉主题与动效组件 ====================
class ClaudeTheme:
    """Claude Code 风格调色板与字符符号"""
    # 核心色彩
    ORANGE = "\033[38;2;217;119;87m"       # Claude 标志性珊瑚暖橙
    ORANGE_BG = "\033[48;2;217;119;87m"
    HIGHLIGHT_BG = "\033[48;2;48;45;48m"  # 优雅深灰选中底色
    CYAN = "\033[38;2;56;189;248m"         # 亮青
    GREEN = "\033[38;2;34;197;94m"        # 柔和亮绿
    YELLOW = "\033[38;2;234;179;8m"       # 暖黄
    RED = "\033[38;2;239;68;68m"          # 警示红
    DIM = "\033[38;2;120;120;128m"        # 灰色副标题
    TEXT = "\033[38;2;225;225;230m"       # 正文白
    WHITE = "\033[38;2;255;255;255m"      # 高亮纯白
    BOLD = "\033[1m"
    RESET = "\033[0m"

    # 图标符号
    POINTER = "❯"
    BULLET = "●"
    CHECK = "✔"
    CROSS = "✖"
    SPARKLE = "✦"
    QUESTION = "?"

def render_spinner(message, duration=0.8):
    """Claude Code 风格平滑 Spinner 动画"""
    frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
    t_end = time.time() + duration
    i = 0
    while time.time() < t_end:
        frame = frames[i % len(frames)]
        sys.stdout.write(f"\r  {ClaudeTheme.ORANGE}{frame}{ClaudeTheme.RESET} {ClaudeTheme.TEXT}{message}{ClaudeTheme.RESET}")
        sys.stdout.flush()
        time.sleep(0.06)
        i += 1
    sys.stdout.write("\r" + " " * (len(message) + 10) + "\r")
    sys.stdout.flush()

def prompt_claude_input(label, default=""):
    T = ClaudeTheme
    hint = f" {T.DIM}[当前: {default}]{T.RESET}" if default else ""
    prompt_str = f"{T.ORANGE}{T.QUESTION}{T.RESET} {T.BOLD}{label}{T.RESET}{hint}: "
    sys.stdout.write(prompt_str)
    sys.stdout.flush()
    try:
        val = input().strip()
        return val if val else default
    except (KeyboardInterrupt, EOFError):
        print()
        return default

def prompt_claude_password(label, has_existing=False):
    T = ClaudeTheme
    hint = f" {T.DIM}[按回车保持原密码]{T.RESET}" if has_existing else ""
    prompt_str = f"{T.ORANGE}{T.QUESTION}{T.RESET} {T.BOLD}{label}{T.RESET}{hint}: "
    sys.stdout.write(prompt_str)
    sys.stdout.flush()

    import msvcrt
    chars = []
    while True:
        try:
            ch = msvcrt.getwch()
            if ch in ['\r', '\n']:
                print()
                break
            elif ch == '\x08':  # Backspace
                if chars:
                    chars.pop()
                    sys.stdout.write('\b \b')
                    sys.stdout.flush()
            elif ch == '\x03':  # Ctrl+C
                print()
                raise KeyboardInterrupt
            elif ord(ch) >= 32:  # 可打印字符
                chars.append(ch)
                sys.stdout.write(f"{T.DIM}•{T.RESET}")
                sys.stdout.flush()
        except Exception:
            break
    res = "".join(chars).strip()
    return res

def calc_display_width(s: str) -> int:
    """
    精确计算终端物理视觉列宽:
    - 自动剔除 ANSI 颜色控制码
    - 标准 ASCII 字符 (英数、空格、标点) 严格计为 1 列宽
    - 中文汉字与全角字符 严格计为 2 列宽
    """
    clean = re.sub(r"\033\[[0-9;]*[a-zA-Z]", "", s)
    w = 0
    for ch in clean:
        if ord(ch) < 128:
            w += 1
        elif unicodedata.east_asian_width(ch) in ("F", "W"):
            w += 2
        else:
            w += 1
    return w

def render_card_box(lines: list, target_width: int = 70, border_color: str = None) -> None:
    """
    全封闭 Claude 风格标准矩形卡片 (右侧绝对闭合对齐)
    采用标准纯等宽规范，彻底根除字体点阵浮点渲染导致的参差不齐问题
    """
    T = ClaudeTheme
    bc = border_color or T.DIM
    border_top = f"{bc}╭" + "─" * (target_width + 2) + f"╮{T.RESET}"
    border_bot = f"{bc}╰" + "─" * (target_width + 2) + f"╯{T.RESET}"
    print(border_top)
    for line in lines:
        w = calc_display_width(line)
        pad = max(0, target_width - w)
        print(f"{bc}│{T.RESET} {line}" + (" " * pad) + f" {bc}│{T.RESET}")
    print(border_bot)

# ==================== CLI 控制面板 ====================
def print_claude_banner():
    T = ClaudeTheme
    line1 = f"{T.ORANGE}{T.BOLD}LZU PORTAL GATEWAY | AUTOMATIC AUTHENTICATION DAEMON{T.RESET}"
    line2 = f"{T.DIM}School Internet (@study / @lzu.edu.cn) Silent Watcher V0.0.1{T.RESET}"
    render_card_box([line1, line2], target_width=70)
    print(f"  {T.ORANGE}{T.SPARKLE}{T.RESET} {T.BOLD}兰州大学校园网自动认证守护助手{T.RESET} {T.DIM}(后台静默检测与一键认证){T.RESET}")

def print_claude_dashboard():
    T = ClaudeTheme
    config = ConfigManager.load()
    username = config.get("username", "")
    domain = config.get("domain", "@study")
    has_pwd = bool(config.get("password_encrypted"))
    autostart = AutoStartManager.is_enabled()
    daemon_pid = get_daemon_pid()

    # 脱敏账号显示
    masked_user = (username[:3] + "***" + username[-2:]) if len(username) > 5 else (username or "未配置")
    if domain == "@study":
        domain_label = "@eLearning"
    elif domain in ["@lzu.edu.cn", ""]:
        domain_label = "@lzu.edu.cn"
    else:
        domain_label = domain

    # 实时网络探测
    client = LzuSrunClient(host=config.get("host", "10.10.0.166"), acid=config.get("acid", "2"))
    net_dot = f"{T.DIM}{T.BULLET}{T.RESET}"
    net_str = "检测中..."
    try:
        if is_lzu_gateway_reachable():
            info = client.get_rad_user_info(timeout=1.5)
            if info.get("error") == "ok":
                net_dot = f"{T.GREEN}{T.BULLET}{T.RESET}"
                net_str = f"{T.GREEN}已连通 LZU 校园网{T.RESET} {T.DIM}(在线: {info.get('user_name')}, IP: {info.get('online_ip')}){T.RESET}"
            else:
                net_dot = f"{T.YELLOW}{T.BULLET}{T.RESET}"
                net_str = f"{T.YELLOW}已连接 LZU 网络{T.RESET} {T.DIM}(处于未认证状态，需登录){T.RESET}"
        else:
            net_dot = f"{T.RED}{T.BULLET}{T.RESET}"
            net_str = f"{T.RED}未检测到 LZU 网络{T.RESET} {T.DIM}(10.10.0.166不可达){T.RESET}"
    except Exception:
        net_dot = f"{T.RED}{T.BULLET}{T.RESET}"
        net_str = f"{T.RED}网络检测异常{T.RESET}"

    daemon_dot = f"{T.GREEN}{T.BULLET}{T.RESET}" if daemon_pid else f"{T.DIM}{T.BULLET}{T.RESET}"
    daemon_str = f"{T.GREEN}运行中{T.RESET} {T.DIM}(PID: {daemon_pid} · 每10s静默轮询){T.RESET}" if daemon_pid else f"{T.DIM}未运行{T.RESET}"

    auto_dot = f"{T.GREEN}{T.BULLET}{T.RESET}" if autostart else f"{T.DIM}{T.BULLET}{T.RESET}"
    auto_str = f"{T.GREEN}已开启{T.RESET} {T.DIM}(Windows Startup 启动文件夹){T.RESET}" if autostart else f"{T.DIM}已关闭{T.RESET}"

    pwd_str = f"{T.GREEN}已保存 (DPAPI 硬件加密){T.RESET}" if has_pwd else f"{T.YELLOW}未设置{T.RESET}"

    print(f"\n{T.BOLD}{T.DIM}SYSTEM STATUS{T.RESET}")
    print(f"  {net_dot} 网络状态      {net_str}")
    print(f"  {daemon_dot} 后台守护      {daemon_str}")
    print(f"  {auto_dot} 开机自启      {auto_str}")
    print(f"  {T.DIM}{T.BULLET}{T.RESET} 上网账号      {T.WHITE}{masked_user}{T.RESET} {T.DIM}({domain_label}){T.RESET}  {T.DIM}│{T.RESET}  密码: {pwd_str}")
    print(f"{T.DIM}────────────────────────────────────────────────────────────────────────{T.RESET}")

def print_subpage_header(ascii_tag: str, zh_title: str, subtitle: str = ""):
    """二级界面专属卡片头部 (自动清空一级界面，关闭一级菜单，全封闭绝对激光对齐)"""
    T = ClaudeTheme
    os.system("cls")
    line1 = f"{T.ORANGE}{T.BOLD}{ascii_tag}{T.RESET}"
    line2 = f"{T.DIM}LZU Srun Portal Management System · Automated CLI{T.RESET}"
    render_card_box([line1, line2], target_width=70)
    print(f"  {T.ORANGE}{T.SPARKLE}{T.RESET} {T.BOLD}{zh_title}{T.RESET}")
    if subtitle:
        print(f"    {T.DIM}{subtitle}{T.RESET}")
    print()

def prompt_config():
    T = ClaudeTheme
    print_subpage_header("CONFIGURATION | USER CREDENTIALS & DOMAIN", "配置上网账号与密码", "设置学号、密码与认证域名，数据采用 Windows DPAPI 硬件级加密保存")
    config = ConfigManager.load()
    curr_user = config.get("username", "")
    new_user = prompt_claude_input("上网账号/学号", curr_user)
    if new_user:
        config["username"] = new_user

    has_pwd = bool(config.get("password_encrypted"))
    new_pwd = prompt_claude_password("上网密码", has_existing=has_pwd)
    if new_pwd:
        config["password_encrypted"] = encrypt_password(new_pwd)

    curr_domain = config.get("domain", "@study")
    default_choice = "1" if curr_domain == "@study" else "2"
    print(f"\n{T.BOLD}请选择认证域名类型:{T.RESET}")
    print(f"  {T.ORANGE}1.{T.RESET} {T.BOLD}@eLearning{T.RESET}    {T.DIM}(学生在线学习专网，域后缀 @study){T.RESET}")
    print(f"  {T.ORANGE}2.{T.RESET} {T.BOLD}@lzu.edu.cn{T.RESET}   {T.DIM}(兰州大学校园网主域认证){T.RESET}")
    choice = prompt_claude_input("请选择认证域名 [1: @eLearning, 2: @lzu.edu.cn]", default_choice)
    if choice == "2":
        config["domain"] = "@lzu.edu.cn"
    else:
        config["domain"] = "@study"

    render_spinner("正在保存配置到本地...", duration=0.4)
    if ConfigManager.save(config):
        print(f"\n  {T.GREEN}{T.CHECK} 上网账号配置已安全保存！(Windows DPAPI 加密已保护){T.RESET}")
        # 默认自动开启后台静默守护服务
        if not get_daemon_pid():
            render_spinner("正在自动开启后台静默守护服务...", duration=0.4)
            ok, msg = start_daemon_process()
            if ok:
                print(f"  {T.GREEN}{T.CHECK} {msg} (默认自动开启后台守护){T.RESET}")
    else:
        print(f"\n  {T.RED}{T.CROSS} 配置文件保存失败，请检查写入权限！{T.RESET}")

def test_login_interactive():
    T = ClaudeTheme
    print_subpage_header("NETWORK TEST | GATEWAY DIAGNOSTICS & LOGIN", "网关连接与一键登录测试", "实时探测 http://10.10.0.166 并发起深澜 Srun 4000 认证")
    config = ConfigManager.load()
    username = config.get("username", "")
    encrypted_pwd = config.get("password_encrypted", "")
    password = decrypt_password(encrypted_pwd)
    domain = config.get("domain", "@study")

    if not username or not password:
        print(f"  {T.YELLOW}{T.CROSS} 尚未配置账号或密码，请先在主菜单选择 [1] 进行配置！{T.RESET}")
        return

    domain_show = "@eLearning" if domain == "@study" else domain
    print(f"  {T.BOLD}发起认证请求: 用户名={username} [{domain_show}]{T.RESET}")
    render_spinner(f"正在探测网关 http://10.10.0.166 (账号: {username} [{domain_show}])...", duration=0.6)

    client = LzuSrunClient(host=config.get("host", "10.10.0.166"), acid=config.get("acid", "2"))
    try:
        render_spinner("正在获取挑战令牌并计算 Srun 签名...", duration=0.5)
        res = client.login(username=username, password=password, domain=domain)
        if res.get("success"):
            print(f"\n  {T.GREEN}{T.CHECK} {res.get('msg')}{T.RESET}")
        else:
            print(f"\n  {T.RED}{T.CROSS} {res.get('msg')}{T.RESET}")
    except Exception as e:
        print(f"\n  {T.RED}{T.CROSS} 认证过程发生异常: {e}{T.RESET}")

def toggle_autostart_interactive():
    T = ClaudeTheme
    curr = AutoStartManager.is_enabled()
    target = not curr
    action_text = "开启" if target else "关闭"
    print_subpage_header("AUTOSTART CONFIG | WINDOWS STARTUP SERVICE", f"{action_text}开机自启动", "配置 Windows Startup 启动目录及注册表自启动项")
    render_spinner(f"正在{action_text} Windows 启动项配置...", duration=0.4)
    ok, msg = AutoStartManager.set_autostart(target)
    if ok:
        print(f"  {T.GREEN}{T.CHECK} {msg}{T.RESET}")
    else:
        print(f"  {T.RED}{T.CROSS} {msg}{T.RESET}")

def show_recent_logs(lines=25):
    T = ClaudeTheme
    print_subpage_header("SYSTEM LOGS | AUTHENTICATION RECORDS", "查看运行与认证日志", f"展示本地 lzu_login.log 最近 {lines} 条记录")
    if not os.path.exists(LOG_FILE):
        print(f"  {T.DIM}暂无日志记录。{T.RESET}")
    else:
        try:
            with open(LOG_FILE, "r", encoding="utf-8", errors="ignore") as f:
                all_lines = f.readlines()
                recent = all_lines[-lines:] if len(all_lines) > lines else all_lines
                for line in recent:
                    clean = line.rstrip()
                    if "[ERROR]" in clean:
                        print(f"  {T.RED}{clean}{T.RESET}")
                    elif "[WARNING]" in clean:
                        print(f"  {T.YELLOW}{clean}{T.RESET}")
                    else:
                        print(f"  {clean}")
        except Exception as e:
            print(f"  {T.RED}读取日志失败: {e}{T.RESET}")
    print(f"\n{T.DIM}────────────────────────────────────────────────────────────────────────{T.RESET}")

def clear_logs():
    T = ClaudeTheme
    print_subpage_header("CLEAR LOGS | PURGE LOCAL RECORD HISTORY", "清空运行日志", "清除本地日志文件以释放磁盘空间")
    if os.path.exists(LOG_FILE):
        try:
            with open(LOG_FILE, "w", encoding="utf-8") as f:
                f.write("")
            print(f"  {T.GREEN}{T.CHECK} 运行日志已成功清空！{T.RESET}")
        except Exception as e:
            print(f"  {T.RED}{T.CROSS} 清空日志失败: {e}{T.RESET}")
    else:
        print(f"  {T.DIM}日志文件不存在，无需清理。{T.RESET}")

def render_menu_block(menu_items, selected_idx, is_redraw=False):
    T = ClaudeTheme
    lines = []
    lines.append(f"{T.ORANGE}{T.QUESTION}{T.RESET} {T.BOLD}选择你的操作{T.RESET} {T.DIM}(用 ↑/↓ 方向键选择回车确认，或直接敲数字键 1~7/0){T.RESET}")
    lines.append("")

    # 动态精确计算所有选项标题 "key. title" 的最大终端视觉列宽，确保说明文字绝对垂直对齐
    max_title_w = max(calc_display_width(f"{k}. {title}") for k, title, _ in menu_items)
    target_w = max_title_w + 3  # 最长标题项后保留 3 个对齐空格

    for i, (key, title, desc) in enumerate(menu_items):
        cur_title = f"{key}. {title}"
        cur_w = calc_display_width(cur_title)
        pad = " " * max(2, target_w - cur_w)

        if i == selected_idx:
            # 选中高亮行: 暖橙指示器 ❯ + 加粗纯白标题 + 垂直对齐的说明文字
            line = f"  {T.ORANGE}{T.BOLD}{T.POINTER}{T.RESET} {T.BOLD}{cur_title}{T.RESET}{pad}{T.DIM}— {desc}{T.RESET}"
        else:
            # 普通行: 灰色序号与标题 + 垂直对齐的说明文字
            line = f"    {T.DIM}{key}.{T.RESET} {T.TEXT}{title}{T.RESET}{pad}{T.DIM}— {desc}{T.RESET}"
        lines.append(line)

    lines.append("")
    lines.append(f"{T.DIM}────────────────────────────────────────────────────────────────────────{T.RESET}")
    lines.append(f"  {T.DIM}💡 推荐一键直达: 键盘直接敲数字 {T.ORANGE}{T.BOLD}1~7{T.RESET}{T.DIM} 或 {T.ORANGE}{T.BOLD}0{T.RESET}{T.DIM} 瞬间触发 (无需回车)；也可用 ↑/↓ 方向键移动回车确认。{T.RESET}")

    total_lines = len(lines)
    if is_redraw:
        # 光标向上跳回总行数位置并重置到行首，原地覆写，0 闪烁
        sys.stdout.write(f"\033[{total_lines}A\r")

    for l in lines:
        sys.stdout.write(f"{l}\033[K\n")
    sys.stdout.flush()

    return total_lines

def run_interactive_menu():
    T = ClaudeTheme
    selected_idx = 0

    # 默认开启后台守护服务策略: 若已配置好账号密码且后台服务未运行，启动面板时自动静默拉起
    config_init = ConfigManager.load()
    if config_init.get("username") and config_init.get("password_encrypted"):
        if not get_daemon_pid():
            start_daemon_process()

    try:
        while True:
            autostart_desc = "关闭开机自启动" if AutoStartManager.is_enabled() else "开启开机自启动"
            daemon_pid = get_daemon_pid()
            daemon_desc = f"停止后台守护服务 {T.DIM}(PID: {daemon_pid}){T.RESET}" if daemon_pid else "启动后台守护服务"

            # 菜单项定义: (快捷键, 标题文字, 辅助说明文字)
            menu_items = [
                ("1", "配置上网账号与密码", "设置学号与密码，DPAPI 本地安全加密"),
                ("2", "立即测试连接与登录", "即刻探测网关并执行一次静默认证"),
                ("3", daemon_desc, "24 小时在系统后台默默监听重连"),
                ("4", f"重启后台守护服务 {T.DIM}({'PID: ' + str(daemon_pid) if daemon_pid else '未运行'}){T.RESET}", "安全重启后台常驻守护进程"),
                ("5", autostart_desc, "开机自动在系统后台静默运行"),
                ("6", "查看实时运行日志", "查看网络检测与深澜认证事件记录"),
                ("7", "清空历史运行日志", "清除本地 lzu_login.log 文件"),
                ("0", "退出控制面板", "退出面板 (后台守护仍会持续静默工作)"),
            ]

            # 1. 仅在初次进入或子操作返回时执行一次全屏重刷
            os.system("cls")
            print_claude_banner()
            print_claude_dashboard()
            print()

            # 绘制菜单
            render_menu_block(menu_items, selected_idx, is_redraw=False)

            action_key = None
            while True:
                k = get_menu_key()
                if k == 'UP':
                    selected_idx = (selected_idx - 1) % len(menu_items)
                    render_menu_block(menu_items, selected_idx, is_redraw=True)
                elif k == 'DOWN':
                    selected_idx = (selected_idx + 1) % len(menu_items)
                    render_menu_block(menu_items, selected_idx, is_redraw=True)
                elif k == 'ENTER':
                    action_key = menu_items[selected_idx][0]
                    break
                elif k == 'ESC':
                    action_key = '0'
                    break
                elif k in '01234567':
                    # 单键瞬间触发秒选
                    for idx, item in enumerate(menu_items):
                        if item[0] == k:
                            selected_idx = idx
                            break
                    render_menu_block(menu_items, selected_idx, is_redraw=True)
                    action_key = k
                    time.sleep(0.06)
                    break

            if action_key is None:
                continue

            print()

            if action_key == "1":
                prompt_config()
                wait_for_return()
            elif action_key == "2":
                test_login_interactive()
                wait_for_return()
            elif action_key == "3":
                action_name = "停止" if daemon_pid else "启动"
                print_subpage_header("DAEMON SERVICE | BACKGROUND NETWORK MONITOR", f"{action_name}后台守护服务", "管理 24 小时断线自动重连后台常驻进程")
                render_spinner(f"正在{action_name}后台守护服务...", duration=0.4)
                if daemon_pid:
                    ok, msg = stop_daemon_process()
                else:
                    ok, msg = start_daemon_process()
                print(f"  {T.GREEN if ok else T.RED}{T.CHECK if ok else T.CROSS} {msg}{T.RESET}")
                wait_for_return()
            elif action_key == "4":
                print_subpage_header("RESTART DAEMON | RELOAD CONFIGURATION", "重启后台守护服务", "安全重新加载配置并重启常驻进程")
                if daemon_pid:
                    render_spinner("正在安全重启后台守护服务...", duration=0.6)
                    stop_daemon_process()
                    time.sleep(0.5)
                    ok, msg = start_daemon_process()
                    print(f"  {T.GREEN if ok else T.RED}{T.CHECK if ok else T.CROSS} {msg}{T.RESET}")
                else:
                    print(f"  {T.DIM}后台守护服务未在运行，无需重启。可在主菜单选择 [3] 启动服务。{T.RESET}")
                wait_for_return()
            elif action_key == "5":
                toggle_autostart_interactive()
                wait_for_return()
            elif action_key == "6":
                show_recent_logs()
                wait_for_return()
            elif action_key == "7":
                clear_logs()
                wait_for_return()
            elif action_key == "0":
                print(f"{T.DIM}已退出控制面板。守护服务若处于运行中，将继续在后台为您静默工作。{T.RESET}")
                break

    except (KeyboardInterrupt, EOFError):
        print(f"\n{T.DIM}操作已取消，退出控制面板。{T.RESET}")

# ==================== CLI 主入口 ====================
def main():
    parser = argparse.ArgumentParser(description="兰州大学校园网自动检测与静默登录助手 (All-in-One)")
    parser.add_argument("--daemon", action="store_true", help="以守护进程模式在后台静默运行 (无控制台窗口)")
    parser.add_argument("--login", action="store_true", help="立即执行一次静默认证登录")
    parser.add_argument("--start", action="store_true", help="在后台启动静默守护进程")
    parser.add_argument("--stop", action="store_true", help="停止正在运行的后台守护进程")
    parser.add_argument("--restart", action="store_true", help="重启后台守护进程")
    parser.add_argument("--status", action="store_true", help="查看当前网络连接与后台守护状态")
    parser.add_argument("--autostart", choices=["on", "off"], help="开启或关闭开机自启动")
    parser.add_argument("--config", action="store_true", help="进入上网账号密码配置流程")

    args = parser.parse_args()

    if args.daemon:
        run_daemon_loop()
    elif args.login:
        config = ConfigManager.load()
        username = config.get("username", "")
        password = decrypt_password(config.get("password_encrypted", ""))
        domain = config.get("domain", "@study")
        if not username or not password:
            print("错误: 尚未配置账号或密码，请先使用 --config 进行配置。")
            sys.exit(1)
        client = LzuSrunClient(host=config.get("host", "10.10.0.166"), acid=config.get("acid", "2"))
        res = client.login(username, password, domain)
        print(res.get("msg"))
        sys.exit(0 if res.get("success") else 1)
    elif args.start:
        ok, msg = start_daemon_process()
        print(msg)
        sys.exit(0 if ok else 1)
    elif args.stop:
        ok, msg = stop_daemon_process()
        print(msg)
        sys.exit(0 if ok else 1)
    elif args.restart:
        stop_daemon_process()
        time.sleep(1)
        ok, msg = start_daemon_process()
        print(msg)
        sys.exit(0 if ok else 1)
    elif args.status:
        print_claude_banner()
        print_claude_dashboard()
    elif args.autostart:
        enable = (args.autostart == "on")
        ok, msg = AutoStartManager.set_autostart(enable)
        print(msg)
        sys.exit(0 if ok else 1)
    elif args.config:
        prompt_config()
    else:
        run_interactive_menu()

if __name__ == "__main__":
    main()


