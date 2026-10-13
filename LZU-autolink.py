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

VERSION = "V0.1.0"
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
import tempfile
import shutil

if sys.platform == "win32":
    import msvcrt

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
        if h_conin and h_conin != -1:
            if kernel32.GetConsoleMode(h_conin, ctypes.byref(mode_in)):
                new_in = (mode_in.value & ~0x0040) | 0x0080 | 0x0010 | 0x0008 | 0x0200
                kernel32.SetConsoleMode(h_conin, new_in)
            kernel32.CloseHandle(h_conin)
        if h_conout and h_conout != -1:
            if kernel32.GetConsoleMode(h_conout, ctypes.byref(mode_out)):
                kernel32.SetConsoleMode(h_conout, mode_out.value | 0x0004 | 0x0001)
            kernel32.CloseHandle(h_conout)
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
    """使用 Windows DPAPI 加密密码 (基于 Windows 用户账户密钥保护体系)"""
    if not password:
        return ""
    try:
        crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
        data_bytes = password.encode("utf-8")
        blob_in = DATA_BLOB(len(data_bytes), ctypes.cast(ctypes.create_string_buffer(data_bytes), ctypes.POINTER(ctypes.c_byte)))
        blob_out = DATA_BLOB()
        if crypt32.CryptProtectData(ctypes.byref(blob_in), "lzu_portal_pwd", None, None, None, 0, ctypes.byref(blob_out)):
            res = ctypes.string_at(blob_out.pbData, blob_out.cbData)
            ctypes.windll.kernel32.LocalFree(blob_out.pbData)
            return "dpapi:" + base64.b64encode(res).decode("utf-8")
        else:
            err = ctypes.get_last_error()
            logger.warning(f"Windows DPAPI (CryptProtectData) 调用失败 (错误码: {err})，降级为 Base64 存储（非安全加密，等同于明文存储）！")
    except Exception as e:
        logger.warning(f"Windows DPAPI 加密发生异常: {e}，降级为 Base64 存储（非安全加密，等同于明文存储）！")
    return "b64:" + base64.b64encode(password.encode("utf-8")).decode("utf-8")

def get_password_security_desc(cipher_text: str) -> tuple[str, str]:
    """返回密码安全状态及显示颜色标记: (描述文本, 颜色类型)"""
    if not cipher_text:
        return "未设置", "yellow"
    if cipher_text.startswith("dpapi:"):
        return "已保存 (Windows 用户账户保护)", "green"
    elif cipher_text.startswith("b64:"):
        return "已保存 (当前为弱加密/明文存储)", "red"
    return "已保存 (明文存储)", "red"

def decrypt_password(cipher_text: str) -> str:
    """使用 Windows DPAPI 解密密码"""
    if not cipher_text:
        return ""
    if cipher_text.startswith("dpapi:"):
        try:
            raw_bytes = base64.b64decode(cipher_text[6:])
            crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
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
    STARTUP_LNK = os.path.join(STARTUP_DIR, "LZU-autolink.lnk")
    LEGACY_VBS_1 = os.path.join(STARTUP_DIR, "LZU-autolink.vbs")
    LEGACY_VBS_2 = os.path.join(STARTUP_DIR, "LZU_AutoLogin.vbs")

    @classmethod
    def is_admin(cls) -> bool:
        """检查当前进程是否具有管理员权限"""
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False

    @classmethod
    def elevate_and_wait(cls, params: str) -> tuple[bool, str]:
        """请求 Windows UAC 管理员提权授权并同步等待子进程完成"""
        class SHELLEXECUTEINFO(ctypes.Structure):
            _fields_ = [
                ("cbSize", wintypes.DWORD),
                ("fMask", wintypes.ULONG),
                ("hwnd", wintypes.HWND),
                ("lpVerb", wintypes.LPCWSTR),
                ("lpFile", wintypes.LPCWSTR),
                ("lpParameters", wintypes.LPCWSTR),
                ("lpDirectory", wintypes.LPCWSTR),
                ("nShow", ctypes.c_int),
                ("hInstApp", wintypes.HINSTANCE),
                ("lpIDList", wintypes.LPVOID),
                ("lpClass", wintypes.LPCWSTR),
                ("hkeyClass", wintypes.HKEY),
                ("dwHotKey", wintypes.DWORD),
                ("hIcon", wintypes.HANDLE),
                ("hProcess", wintypes.HANDLE)
            ]

        sei = SHELLEXECUTEINFO()
        sei.cbSize = ctypes.sizeof(SHELLEXECUTEINFO)
        sei.fMask = 0x00000040  # SEE_MASK_NOCLOSEPROCESS
        sei.hwnd = None
        sei.lpVerb = "runas"

        if getattr(sys, "frozen", False):
            sei.lpFile = sys.executable
            sei.lpParameters = params
            sei.lpDirectory = os.path.dirname(os.path.abspath(sys.executable))
        else:
            sei.lpFile = sys.executable
            sei.lpParameters = f'"{os.path.abspath(__file__)}" {params}'
            sei.lpDirectory = os.path.dirname(os.path.abspath(__file__))

        sei.nShow = 0  # SW_HIDE

        s32 = ctypes.WinDLL("shell32", use_last_error=True)
        ret = s32.ShellExecuteExW(ctypes.byref(sei))
        if not ret:
            err = ctypes.get_last_error()
            if err == 1223:  # ERROR_CANCELLED (用户在UAC界面点击了“否”)
                return False, "用户取消了系统管理员权限授权。"
            return False, f"申请管理员权限失败 (错误代码: {err})"

        if sei.hProcess:
            # 同步等待管理员提权子进程执行完成 (最多等待 20 秒)
            WAIT_OBJECT_0 = 0x00000000
            WAIT_TIMEOUT = 0x00000102
            k32 = ctypes.WinDLL("kernel32", use_last_error=True)
            wait_ret = k32.WaitForSingleObject(sei.hProcess, 20000)
            
            if wait_ret == WAIT_OBJECT_0:
                exit_code = wintypes.DWORD()
                k32.GetExitCodeProcess(sei.hProcess, ctypes.byref(exit_code))
                k32.CloseHandle(sei.hProcess)
                if exit_code.value == 0:
                    return True, "已成功获取管理员权限并完成开机自启动配置！"
                else:
                    return False, f"管理员提权操作返回错误 (退出码: {exit_code.value})"
            elif wait_ret == WAIT_TIMEOUT:
                k32.CloseHandle(sei.hProcess)
                return False, "管理员提权操作执行超时 (超过 20 秒未完成)，请稍后重试。"
            else:
                k32.CloseHandle(sei.hProcess)
                return False, f"等待管理员提权子进程失败 (等待返回码: {wait_ret})"

        return True, "已请求管理员授权"

    @classmethod
    def get_pythonw_path(cls):
        py_dir = os.path.dirname(sys.executable)
        pythonw_path = os.path.join(py_dir, "pythonw.exe")
        if os.path.exists(pythonw_path):
            return pythonw_path
        return sys.executable

    @classmethod
    def get_target_and_args(cls) -> tuple[str, str, str]:
        if getattr(sys, "frozen", False):
            target = os.path.abspath(sys.executable)
            args = "--daemon"
            work_dir = os.path.dirname(target)
        else:
            target = cls.get_pythonw_path()
            script_file = os.path.abspath(__file__)
            args = f'"{script_file}" --daemon'
            work_dir = os.path.dirname(script_file)
        return target, args, work_dir

    @classmethod
    def create_shortcut(cls, target_path: str, args: str, work_dir: str) -> bool:
        """使用 Windows 原生 COM 接口写入启动快捷方式 (.lnk)"""
        try:
            os.makedirs(cls.STARTUP_DIR, exist_ok=True)
            try:
                import win32com.client
                shell = win32com.client.Dispatch("WScript.Shell")
                shortcut = shell.CreateShortCut(cls.STARTUP_LNK)
                shortcut.TargetPath = target_path
                shortcut.Arguments = args
                shortcut.WorkingDirectory = work_dir
                shortcut.WindowStyle = 7
                shortcut.Description = "兰州大学校园网自动登录守护进程"
                shortcut.Save()
                if os.path.exists(cls.STARTUP_LNK):
                    return True
            except Exception as e_com:
                logger.warning(f"win32com 写入快捷方式失败: {e_com}")

            # 回退方案: 标准纯文本 PowerShell 命令 (使用单引号字面量与转义，避免源码模式下 args 包含双引号导致意外的标记语法错误)
            def _ps_quote(s: str) -> str:
                return "'" + s.replace("'", "''") + "'"

            CREATE_NO_WINDOW = 0x08000000
            safe_ps = f'$ws = New-Object -ComObject WScript.Shell; $s = $ws.CreateShortcut({_ps_quote(cls.STARTUP_LNK)}); $s.TargetPath = {_ps_quote(target_path)}; $s.Arguments = {_ps_quote(args)}; $s.WorkingDirectory = {_ps_quote(work_dir)}; $s.WindowStyle = 7; $s.Save()'
            subprocess.run(
                ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", safe_ps],
                capture_output=True,
                creationflags=CREATE_NO_WINDOW,
                timeout=5
            )
            return os.path.exists(cls.STARTUP_LNK)
        except Exception as e:
            logger.warning(f"创建启动快捷方式失败: {e}")
            return False

    @classmethod
    def is_enabled(cls) -> bool:
        if os.path.exists(cls.STARTUP_LNK) or os.path.exists(cls.LEGACY_VBS_1) or os.path.exists(cls.LEGACY_VBS_2):
            return True
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
    def _set_autostart_direct(cls, enable: bool) -> bool:
        """底层直接执行写入或清除自启动项 (单一机制: 仅使用 Windows 启动文件夹快捷方式，彻底杜绝双自启动实例)"""
        target, args, work_dir = cls.get_target_and_args()
        if enable:
            # 单一自启源: 仅写入用户 Startup 文件夹快捷方式
            lnk_ok = cls.create_shortcut(target, args, work_dir)
            # 主动清理注册表 Run 项中的历史残留，确保绝不发生双自启并发
            try:
                key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, cls.REG_KEY, 0, winreg.KEY_SET_VALUE)
                winreg.DeleteValue(key, cls.APP_NAME)
                winreg.CloseKey(key)
            except Exception:
                pass
            return lnk_ok or os.path.exists(cls.STARTUP_LNK)
        else:
            cleaned = False
            for path in [cls.STARTUP_LNK, cls.LEGACY_VBS_1, cls.LEGACY_VBS_2]:
                if os.path.exists(path):
                    try:
                        os.remove(path)
                        cleaned = True
                    except Exception:
                        pass
            try:
                key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, cls.REG_KEY, 0, winreg.KEY_SET_VALUE)
                winreg.DeleteValue(key, cls.APP_NAME)
                winreg.CloseKey(key)
                cleaned = True
            except Exception:
                pass
            return cleaned or not cls.is_enabled()

    @classmethod
    def set_autostart(cls, enable: bool) -> tuple[bool, str]:
        # 1. 尝试当前权限直接写入或清理
        ok = cls._set_autostart_direct(enable)
        if ok:
            msg = "已成功开启开机自启动！(电脑开机将自动在后台静默运行守护)" if enable else "已成功关闭开机自启动！"
            logger.info(msg)
            return True, msg

        # 2. 当前权限受限时，若未具备管理员权限，自动申请 UAC 管理员提权
        if not cls.is_admin():
            action_param = "--autostart on" if enable else "--autostart off"
            logger.info("当前权限受限，正在请求 Windows 系统管理员 UAC 权限...")
            elev_ok, elev_msg = cls.elevate_and_wait(action_param)
            if elev_ok:
                logger.info("管理员提权设置自启动成功")
                return True, elev_msg
            else:
                return False, elev_msg

        return False, "未能写入开机自启动项，请检查杀毒软件或系统权限设置。"

# ==================== 经典 Srun 编解码算法 ====================
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

def get_current_wifi_ssid() -> str | None:
    """获取当前连接的 Windows Wi-Fi 网络名称 (SSID)，支持 iLZU / LZU 等网络识别 (兼容中文 Windows 控制台编码)"""
    try:
        CREATE_NO_WINDOW = 0x08000000
        res = subprocess.run(
            ["netsh", "wlan", "show", "interfaces"],
            capture_output=True,
            text=True,
            errors="replace",
            creationflags=CREATE_NO_WINDOW
        )
        for line in res.stdout.splitlines():
            line_strip = line.strip()
            if line_strip.startswith("SSID") and ":" in line_strip:
                if not line_strip.startswith("BSSID") and not line_strip.startswith("AP BSSID"):
                    ssid = line_strip.split(":", 1)[1].strip()
                    if ssid:
                        return ssid
    except Exception:
        pass
    return None

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

DAEMON_MASTER_MUTEX = "Local\\LZU_Autolink_Daemon_Mutex"
DAEMON_PID_MUTEX_PREFIX = "Local\\LZU_Autolink_PID_"
DAEMON_STOP_EVENT = "Local\\LZU_Autolink_Stop_Event"
STOP_FLAG = os.path.join(SCRIPT_DIR, "daemon.stop")

def cleanup_orphan_mei_dirs():
    """扫描并清理工作区、runtime 专用子目录中残留的孤儿 _MEI 临时解压目录 (带微重试与当前进程保护)"""
    # 仅清理本程序自己工作目录下的解压残留；绝不扫描系统 %TEMP% 做无差别删除，
    # 否则会误伤其他正在运行的 PyInstaller onefile 程序的 _MEI 解压目录 (部分删除会导致其崩溃)
    search_dirs = [SCRIPT_DIR, os.path.join(SCRIPT_DIR, "runtime")]
    current_mei = getattr(sys, "_MEIPASS", "")
    for base_dir in search_dirs:
        try:
            for entry in os.listdir(base_dir):
                if entry.startswith("_MEI") and os.path.isdir(os.path.join(base_dir, entry)):
                    full_path = os.path.join(base_dir, entry)
                    if current_mei and os.path.abspath(full_path) == os.path.abspath(current_mei):
                        continue
                    for _ in range(5):
                        try:
                            shutil.rmtree(full_path)
                            break
                        except Exception:
                            time.sleep(0.1)
        except Exception:
            pass

def is_stop_requested() -> bool:
    """检测是否收到了停止信号 (文件标志或 Windows 原生命名事件)"""
    if os.path.exists(STOP_FLAG):
        return True
    SYNCHRONIZE = 0x00100000
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    h_event = k32.OpenEventW(SYNCHRONIZE, False, DAEMON_STOP_EVENT)
    if h_event:
        WAIT_OBJECT_0 = 0
        signaled = (k32.WaitForSingleObject(h_event, 0) == WAIT_OBJECT_0)
        k32.CloseHandle(h_event)
        if signaled:
            return True
    return False

def interruptible_sleep(seconds: float) -> bool:
    """可中断休眠：支持毫秒级响应外部停止信号，返回 True 表示需要立即退出"""
    end_time = time.time() + seconds
    while time.time() < end_time:
        if is_stop_requested():
            return True
        time.sleep(0.1)
    return False

def is_daemon_mutex_held() -> bool:
    """检测系统中是否有守护进程正持有主互斥锁 (纯探测，不改变或争夺所有权)"""
    SYNCHRONIZE = 0x00100000
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    h_mutex = k32.OpenMutexW(SYNCHRONIZE, False, DAEMON_MASTER_MUTEX)
    if h_mutex:
        k32.CloseHandle(h_mutex)
        return True
    return False

def is_pid_mutex_held(pid: int) -> bool:
    """检测指定 PID 是否持有守护进程专属互斥体 (毫秒级精准反查)"""
    if pid <= 0:
        return False
    SYNCHRONIZE = 0x00100000
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    h_mutex = k32.OpenMutexW(SYNCHRONIZE, False, f"{DAEMON_PID_MUTEX_PREFIX}{pid}")
    if h_mutex:
        k32.CloseHandle(h_mutex)
        return True
    return False

def find_running_daemon_pid() -> int | None:
    """通过反查 PID 专属互斥体，毫秒级精准定位真实存活的守护进程 PID (0 进程名依赖，0 命令行依赖，绝无误判/漏判)"""
    my_pid = os.getpid()
    TH32CS_SNAPPROCESS = 0x00000002

    class PROCESSENTRY32(ctypes.Structure):
        _fields_ = [
            ("dwSize", wintypes.DWORD),
            ("cntUsage", wintypes.DWORD),
            ("th32ProcessID", wintypes.DWORD),
            ("th32DefaultHeapID", ctypes.c_size_t),
            ("th32ModuleID", wintypes.DWORD),
            ("cntThreads", wintypes.DWORD),
            ("th32ParentProcessID", wintypes.DWORD),
            ("pcPriClassBase", ctypes.c_long),
            ("dwFlags", wintypes.DWORD),
            ("szExeFile", ctypes.c_char * 260)
        ]

    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    h_snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if not h_snap:
        return None

    pe = PROCESSENTRY32()
    pe.dwSize = ctypes.sizeof(PROCESSENTRY32)
    pids = []
    if k32.Process32First(h_snap, ctypes.byref(pe)):
        while True:
            p = pe.th32ProcessID
            if p != my_pid and p > 4 and is_pid_alive(p):
                pids.append(p)
            if not k32.Process32Next(h_snap, ctypes.byref(pe)):
                break
    k32.CloseHandle(h_snap)

    for p in pids:
        if is_pid_mutex_held(p):
            return p
    return None

def get_daemon_pid() -> int | None:
    """获取后台守护进程 PID (具备专属互斥锁感知与自愈恢复能力)"""
    cached_pid = None
    if os.path.exists(PID_FILE):
        try:
            with open(PID_FILE, "r", encoding="utf-8") as f:
                cached_pid = int(f.read().strip())
        except Exception:
            cached_pid = None

    # 1. 优先验证当前 PID 文件中的进程是否存活且真正持有专属守护锁 (严禁宽松放行，彻底杜绝 PID 复用误判)
    if cached_pid and is_pid_alive(cached_pid):
        if is_pid_mutex_held(cached_pid):
            return cached_pid

    # 2. 若 PID 文件缺失、失效或被清空，但系统主互斥锁被持有：通过互斥体反查自愈
    if is_daemon_mutex_held():
        real_pid = find_running_daemon_pid()
        if real_pid:
            try:
                with open(PID_FILE, "w", encoding="utf-8") as f:
                    f.write(str(real_pid))
                logger.info(f"检测到守护互斥锁有效但 PID 文件失步，已自愈写回真实 PID: {real_pid}")
            except Exception:
                pass
            return real_pid

    # 3. 互斥体未被持有且 PID 已死亡 -> 清理无效文件
    if os.path.exists(PID_FILE):
        try:
            os.remove(PID_FILE)
        except Exception:
            pass
    return None

def start_daemon_process():
    """以静默无窗口模式启动后台守护进程 (防脱钩、防误报设计)"""
    pid = get_daemon_pid()
    if pid:
        return False, f"后台守护服务已在运行 (PID: {pid})"

    # 启动前顺带清扫历史孤儿 _MEI 目录
    cleanup_orphan_mei_dirs()

    # 确保清除历史残留的 stop 信号
    if os.path.exists(STOP_FLAG):
        try:
            os.remove(STOP_FLAG)
        except Exception:
            pass

    if getattr(sys, "frozen", False):
        cmd = [sys.executable, "--daemon"]
    else:
        pythonw_path = AutoStartManager.get_pythonw_path()
        cmd = [pythonw_path, os.path.abspath(__file__), "--daemon"]

    CREATE_NO_WINDOW = 0x08000000
    DETACHED_PROCESS = 0x00000008
    try:
        proc = subprocess.Popen(cmd, creationflags=CREATE_NO_WINDOW | DETACHED_PROCESS, close_fds=True)

        started = False
        for _ in range(20):
            time.sleep(0.1)
            if not is_pid_alive(proc.pid):
                break
            if is_pid_mutex_held(proc.pid):
                started = True
                break

        if started:
            try:
                with open(PID_FILE, "w", encoding="utf-8") as f:
                    f.write(str(proc.pid))
            except Exception:
                pass
            logger.info(f"后台守护服务启动成功 (PID: {proc.pid})")
            return True, f"后台守护服务已成功启动！(PID: {proc.pid})"
        else:
            real_pid = get_daemon_pid()
            if real_pid:
                return False, f"后台守护服务已在运行 (PID: {real_pid})"
            return False, "后台守护进程未能成功持锁运行。"
    except Exception as e:
        logger.error(f"启动守护进程失败: {e}")
        return False, f"启动失败: {e}"

def stop_daemon_process():
    """优雅停止后台守护进程 (先发温和信号让 Bootloader 自动清理解压目录，超时再兜底 taskkill)"""
    pid = get_daemon_pid()
    if not pid:
        if os.path.exists(PID_FILE):
            os.remove(PID_FILE)
        return False, "后台守护进程未在运行"
    
    # 1. 发送优雅退出信号
    try:
        with open(STOP_FLAG, "w", encoding="utf-8") as f:
            f.write(str(int(time.time())))
    except Exception:
        pass

    EVENT_MODIFY_STATE = 0x0002
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    h_event = k32.OpenEventW(EVENT_MODIFY_STATE, False, DAEMON_STOP_EVENT)
    if h_event:
        k32.SetEvent(h_event)
        k32.CloseHandle(h_event)

    # 2. 温和等待进程优雅退出，给 PyInstaller Bootloader 充分时间清理解压目录
    stopped_gracefully = False
    for _ in range(30):
        time.sleep(0.1)
        if not is_pid_alive(pid):
            stopped_gracefully = True
            break

    # 3. 若超时仍未退出，执行 taskkill /F 兜底
    if not stopped_gracefully and is_pid_alive(pid):
        logger.warning(f"守护进程 (PID: {pid}) 优雅退出超时，执行强制终止兜底...")
        subprocess.run(["taskkill", "/F", "/PID", str(pid)], capture_output=True, creationflags=0x08000000)

    # 4. 清理标志文件
    for fpath in [STOP_FLAG, PID_FILE]:
        if os.path.exists(fpath):
            try:
                os.remove(fpath)
            except Exception:
                pass

    # 5. 缓冲 0.4 秒确保 Windows 内核彻底关闭目标进程的 DLL 映像句柄，并清理其解压目录
    time.sleep(0.4)
    cleanup_orphan_mei_dirs()

    logger.info(f"后台守护服务已停止 (PID: {pid})")
    return True, f"已成功停止守护服务 (PID: {pid})"

# ==================== 后台守护核心循环 ====================
def run_daemon_loop():
    """后台长期运行的网络监听循环 (具备原子双互斥锁保护与优雅退出机制)"""
    my_pid = os.getpid()

    # 1. Windows 原生命名主互斥体原子排他锁
    ERROR_ALREADY_EXISTS = 183
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    master_mutex = k32.CreateMutexW(None, False, DAEMON_MASTER_MUTEX)
    if master_mutex and ctypes.get_last_error() == ERROR_ALREADY_EXISTS:
        real_pid = find_running_daemon_pid()
        if real_pid:
            try:
                with open(PID_FILE, "w", encoding="utf-8") as f:
                    f.write(str(real_pid))
            except Exception:
                pass
        logger.warning(f"检测到系统已持有守护进程全局互斥锁，当前重复实例 (PID: {my_pid}) 自动退出，防止重复实例并发！")
        if master_mutex:
            k32.CloseHandle(master_mutex)
        sys.exit(0)

    # 2. 创建专属 PID 反查互斥体与停止事件句柄
    pid_mutex = k32.CreateMutexW(None, False, f"{DAEMON_PID_MUTEX_PREFIX}{my_pid}")
    stop_event = k32.CreateEventW(None, True, False, DAEMON_STOP_EVENT)

    # 3. 确认为唯一持锁主实例后，记录 PID 文件
    try:
        with open(PID_FILE, "w", encoding="utf-8") as f:
            f.write(str(my_pid))
    except Exception as e_pid:
        logger.error(f"写入 PID 文件失败: {e_pid}")
    
    logger.info(f"=== LZU 校园网守护进程启动 (PID: {my_pid}) ===")

    fail_count = 0
    logged_no_cred = False
    try:
        while True:
            if is_stop_requested():
                logger.info("收到优雅停止请求，守护进程安全退出...")
                break

            # 单次迭代级异常兜底: 网关抽风/响应畸形等临时故障绝不允许杀死守护进程
            try:
                config = ConfigManager.load()
                try:
                    raw_interval = int(config.get("check_interval", 10))
                except (ValueError, TypeError):
                    raw_interval = 10
                # 严格限制在 [5, 3600] 秒安全区间，杜绝 0 或负数导致 CPU 忙等狂刷网关
                interval = max(5, min(3600, raw_interval))
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
                    if interruptible_sleep(interval):
                        break
                    continue

                # 2. 外网不通，检查是否在兰大内网环境
                if is_lzu_gateway_reachable(host=host, timeout=2.0):
                    client = LzuSrunClient(host=host, acid=acid)
                    info = client.get_rad_user_info(timeout=2.0)

                    # 检查深澜在线状态
                    if info.get("error") == "not_online_error" or not info.get("user_name"):
                        cur_ssid = get_current_wifi_ssid()
                        # 校园无线 SSID 智能过滤: 若连入非兰大无线网 (非 iLZU / LZU)，静默跳过防误触
                        if cur_ssid:
                            s_lower = cur_ssid.lower()
                            if "ilzu" not in s_lower and "lzu" not in s_lower:
                                if interruptible_sleep(interval):
                                    break
                                continue

                        net_label = cur_ssid if cur_ssid else "iLZU/LZU/有线"
                        logger.info(f"检测到已连接 {net_label} 校园网络且处于未认证状态，准备执行静默登录...")
                        if not username or not password:
                            if not logged_no_cred:
                                logger.warning("未配置有效的上网账号或密码，守护服务处于待命状态 (请先运行程序配置账号密码)！")
                                logged_no_cred = True
                            if interruptible_sleep(30):
                                break
                            continue
                        logged_no_cred = False

                        # 执行认证登录
                        res = client.login(username=username, password=password, domain=domain)
                        if res.get("success"):
                            logger.info(f"静默登录成功！详情: {res.get('msg')}")
                            fail_count = 0
                            if interruptible_sleep(interval):
                                break
                        else:
                            logger.error(f"静默登录失败: {res.get('msg')}")
                            fail_count += 1
                            sleep_time = min(30 * fail_count, 120)
                            if interruptible_sleep(sleep_time):
                                break
                else:
                    if interruptible_sleep(interval):
                        break
            except Exception as e_iter:
                logger.error(f"守护循环单次迭代异常 (已自动恢复，10s 后继续监听): {e_iter}")
                if interruptible_sleep(10):
                    break
    except Exception as e_loop:
        logger.error(f"守护主循环异常: {e_loop}")
    finally:
        # 退出清理
        for fpath in [PID_FILE, STOP_FLAG]:
            if os.path.exists(fpath):
                try:
                    os.remove(fpath)
                except Exception:
                    pass
        if master_mutex:
            k32.CloseHandle(master_mutex)
        if pid_mutex:
            k32.CloseHandle(pid_mutex)
        if stop_event:
            k32.CloseHandle(stop_event)
        logger.info(f"=== LZU 校园网守护进程已正常终止并释放所有句柄 (PID: {my_pid}) ===")

# ==================== Claude 风格终端主题与组件 ====================
class ClaudeTheme:
    ORANGE = "\033[38;2;217;119;87m"   # Claude 经典陶土橙
    BOLD = "\033[1m"
    DIM = "\033[38;2;120;120;128m"    # 优雅沉稳的中性灰
    TEXT = "\033[38;2;228;228;231m"   # 纯白/近白文字
    WHITE = "\033[38;2;255;255;255m"
    GREEN = "\033[38;2;34;197;94m"    # 清新绿
    YELLOW = "\033[38;2;234;179;8m"   # 暖黄
    RED = "\033[38;2;239;68;68m"      # 珊瑚红
    RESET = "\033[0m"

    POINTER = "❯"
    CHECK = "✔"
    CROSS = "✘"
    SPARKLE = "✦"
    BULLET = "●"
    QUESTION = "?"

def calc_display_width(s: str) -> int:
    """计算包含中文全角与 ANSI 转义序列字符串在终端的实际显示列宽"""
    s_clean = re.sub(r'\033\[[0-9;]*[a-zA-Z]', '', s)
    w = 0
    for ch in s_clean:
        w += 2 if unicodedata.east_asian_width(ch) in ('F', 'W') else 1
    return w

def render_card_box(lines: list[str], target_width: int = 70):
    """渲染优雅的 Claude 风格圆角细线卡片边框"""
    T = ClaudeTheme
    bc = T.DIM
    border_top = f"{bc}╭" + ("─" * (target_width + 2)) + f"╮{T.RESET}"
    border_bot = f"{bc}╰" + ("─" * (target_width + 2)) + f"╯{T.RESET}"
    print(border_top)
    for line in lines:
        w = calc_display_width(line)
        pad = max(0, target_width - w)
        print(f"{bc}│{T.RESET} {line}" + (" " * pad) + f" {bc}│{T.RESET}")
    print(border_bot)

def print_subpage_header(tag: str, title: str, subtitle: str):
    """清除终端屏幕并输出清晰整洁的二级子页面沉浸式标题头"""
    T = ClaudeTheme
    os.system("cls" if os.name == "nt" else "clear")
    tag_line = f"{T.ORANGE}{T.BOLD}{tag}{T.RESET}"
    render_card_box([tag_line], target_width=70)
    print(f"  {T.ORANGE}{T.SPARKLE}{T.RESET} {T.BOLD}{title}{T.RESET} {T.DIM}({subtitle}){T.RESET}\n")
    print(f"{T.DIM}" + "─" * 72 + f"{T.RESET}")

def render_spinner(text: str, duration: float = 0.5):
    """优雅轻量的字符转轮动效"""
    T = ClaudeTheme
    frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
    end_time = time.time() + duration
    idx = 0
    while time.time() < end_time:
        sys.stdout.write(f"\r  {T.ORANGE}{frames[idx % len(frames)]}{T.RESET} {text}")
        sys.stdout.flush()
        time.sleep(0.06)
        idx += 1
    sys.stdout.write("\r" + " " * (len(text) + 10) + "\r")
    sys.stdout.flush()

def prompt_claude_input(prompt_text: str, default_val: str = "") -> str:
    """仿 Claude Code 命令行输入提示符"""
    T = ClaudeTheme
    def_str = f" {T.DIM}[当前: {default_val}]{T.RESET}" if default_val else ""
    try:
        val = input(f"  {T.ORANGE}{T.QUESTION}{T.RESET} {prompt_text}{def_str}: ").strip()
        return val if val else default_val
    except (KeyboardInterrupt, EOFError):
        return default_val

def prompt_claude_password(prompt_text: str, has_existing: bool = False) -> str:
    """仿 Claude Code 密码输入 (支持密码掩码与保留已有密码)"""
    T = ClaudeTheme
    def_str = f" {T.DIM}[已有已保存密码，直接回车保留]{T.RESET}" if has_existing else ""
    print(f"  {T.ORANGE}{T.QUESTION}{T.RESET} {prompt_text}{def_str}: ", end="", flush=True)
    try:
        pwd = []
        while True:
            ch = msvcrt.getch()
            if ch in (b"\r", b"\n"):
                print()
                break
            elif ch in (b"\x00", b"\xe0"):
                # Windows 扩展键前缀 (方向键、功能键、Insert/Delete等)，吞掉紧随其后的扫描码，杜绝垃圾字符污染密码
                msvcrt.getch()
                continue
            elif ch == b"\x08":  # Backspace
                if pwd:
                    pwd.pop()
                    sys.stdout.write("\b \b")
                    sys.stdout.flush()
            elif ch == b"\x03":  # Ctrl+C
                print()
                return ""
            else:
                try:
                    c = ch.decode("utf-8")
                    if ord(c) >= 32:  # 仅接收标准可打印字符，过滤不可见控制符
                        pwd.append(c)
                        sys.stdout.write(f"{T.DIM}•{T.RESET}")
                        sys.stdout.flush()
                except Exception:
                    pass
        return "".join(pwd)
    except Exception:
        return ""

def get_menu_key():
    """Windows 无延迟按键读取 (同时兼容经典扫描码与 VT 转义序列两种方向键通路，支持空格确认/Delete返回)"""
    ch = msvcrt.getch()
    if ch in (b"\xe0", b"\x00"):
        # 经典扩展键扫描码通路: H=↑ P=↓ S=Delete
        sub = msvcrt.getch()
        if sub == b"H":
            return "UP"
        elif sub == b"P":
            return "DOWN"
        elif sub == b"S":
            return "DELETE"
        return None
    if ch == b"\x1b":
        # VT 序列通路: 控制台初始化启用了 ENABLE_VIRTUAL_TERMINAL_INPUT (0x0200)，
        # 方向键会以 \x1b[A / \x1b[B (或 \x1bOA/\x1bOB) 转义序列形式逐字节到达；
        # 若 ESC 后紧跟后续字符则按功能键序列解析，否则视为单独按下 ESC。
        time.sleep(0.02)
        if msvcrt.kbhit():
            sub1 = msvcrt.getch()
            if sub1 in (b"[", b"O") and msvcrt.kbhit():
                sub2 = msvcrt.getch()
                if sub2 == b"A":
                    return "UP"
                elif sub2 == b"B":
                    return "DOWN"
            return None
        return "ESC"
    if ch == b"\r" or ch == b" ":
        return "ENTER"
    if ch == b"\x08":
        return "BACKSPACE"
    if ch == b"\x03":  # Ctrl+C
        raise KeyboardInterrupt
    try:
        return ch.decode("utf-8", errors="ignore").lower()
    except Exception:
        return None

def print_claude_banner():
    T = ClaudeTheme
    line1 = f"{T.ORANGE}{T.BOLD}LZU PORTAL GATEWAY | AUTOMATIC AUTHENTICATION DAEMON{T.RESET}"
    line2 = f"{T.DIM}School Internet (@eLearning / @lzu.edu.cn) Silent Watcher {VERSION}{T.RESET}"
    render_card_box([line1, line2], target_width=70)
    print(f"  {T.ORANGE}{T.SPARKLE}{T.RESET} {T.BOLD}兰州大学校园网自动认证守护助手{T.RESET} {T.DIM}(后台静默检测与一键认证){T.RESET}")

def print_claude_dashboard():
    cleanup_orphan_mei_dirs()
    T = ClaudeTheme
    config = ConfigManager.load()
    username = config.get("username", "")
    domain = config.get("domain", "@study")
    encrypted_pwd = config.get("password_encrypted", "")
    has_pwd = bool(encrypted_pwd)
    autostart = AutoStartManager.is_enabled()
    daemon_pid = get_daemon_pid()
    host = config.get("host", "10.10.0.166")
    acid = config.get("acid", "2")
    try:
        raw_interval = int(config.get("check_interval", 10))
    except (ValueError, TypeError):
        raw_interval = 10
    interval = max(5, min(3600, raw_interval))

    # 脱敏账号显示
    masked_user = (username[:3] + "***" + username[-2:]) if len(username) > 5 else (username or "未配置")
    if domain == "@study":
        domain_label = "@eLearning"
    elif domain in ["@lzu.edu.cn", ""]:
        domain_label = "@lzu.edu.cn"
    else:
        domain_label = domain

    # 实时网络探测 (智能识别 iLZU / LZU 等无线网络)
    client = LzuSrunClient(host=host, acid=acid)
    wifi_ssid = get_current_wifi_ssid()
    net_label = wifi_ssid if wifi_ssid else "iLZU/LZU"
    net_dot = f"{T.DIM}{T.BULLET}{T.RESET}"
    net_str = "检测中..."
    try:
        if is_lzu_gateway_reachable(host=host):
            info = client.get_rad_user_info(timeout=1.5)
            if info.get("error") == "ok":
                net_dot = f"{T.GREEN}{T.BULLET}{T.RESET}"
                net_str = f"{T.GREEN}已连通 {net_label} 校园网{T.RESET} {T.DIM}(在线: {info.get('user_name')}, IP: {info.get('online_ip')}){T.RESET}"
            else:
                net_dot = f"{T.YELLOW}{T.BULLET}{T.RESET}"
                net_str = f"{T.YELLOW}已连接 {net_label} 网络{T.RESET} {T.DIM}(处于未认证状态，需登录){T.RESET}"
        else:
            net_dot = f"{T.RED}{T.BULLET}{T.RESET}"
            if wifi_ssid:
                net_str = f"{T.RED}未连接校园网{T.RESET} {T.DIM}(当前 Wi-Fi: {wifi_ssid} · {host}网关不可达){T.RESET}"
            else:
                net_str = f"{T.RED}未检测到 iLZU/LZU 校园网{T.RESET} {T.DIM}({host}不可达){T.RESET}"
    except Exception:
        net_dot = f"{T.RED}{T.BULLET}{T.RESET}"
        net_str = f"{T.RED}网络检测异常{T.RESET}"

    daemon_dot = f"{T.GREEN}{T.BULLET}{T.RESET}" if daemon_pid else f"{T.DIM}{T.BULLET}{T.RESET}"
    daemon_str = f"{T.GREEN}运行中{T.RESET} {T.DIM}(PID: {daemon_pid} · 每{interval}s静默轮询){T.RESET}" if daemon_pid else f"{T.DIM}未运行{T.RESET}"

    auto_dot = f"{T.GREEN}{T.BULLET}{T.RESET}" if autostart else f"{T.DIM}{T.BULLET}{T.RESET}"
    auto_str = f"{T.GREEN}已开启{T.RESET} {T.DIM}(Windows Startup 启动文件夹){T.RESET}" if autostart else f"{T.DIM}已关闭{T.RESET}"

    pwd_desc, pwd_level = get_password_security_desc(encrypted_pwd)
    if pwd_level == "green":
        pwd_str = f"{T.GREEN}{pwd_desc}{T.RESET}"
    elif pwd_level == "red":
        pwd_str = f"{T.RED}{pwd_desc}{T.RESET}"
    else:
        pwd_str = f"{T.YELLOW}{pwd_desc}{T.RESET}"

    print(f"\n{T.BOLD}{T.DIM}SYSTEM STATUS{T.RESET}")
    print(f"  {net_dot} 网络状态       {net_str}")
    print(f"  {daemon_dot} 后台守护       {daemon_str}")
    print(f"  {auto_dot} 开机自启       {auto_str}")
    print(f"  {T.DIM}{T.BULLET}{T.RESET} 上网账号       {T.BOLD}{masked_user}{T.RESET} {T.DIM}({domain_label}){T.RESET}   {T.DIM}│{T.RESET}  密码:  {pwd_str}")
    print(f"{T.DIM}" + "─" * 72 + f"{T.RESET}")

def test_login_interactive():
    T = ClaudeTheme
    config = ConfigManager.load()
    host = config.get("host", "10.10.0.166")
    acid = config.get("acid", "2")
    print_subpage_header("NETWORK TEST | GATEWAY DIAGNOSTICS & LOGIN", "网关连接与一键登录测试", f"实时探测 http://{host} 并发起认证")
    username = config.get("username", "")
    encrypted_pwd = config.get("password_encrypted", "")
    password = decrypt_password(encrypted_pwd)
    domain = config.get("domain", "@study")

    if not username or not password:
        print(f"  {T.YELLOW}{T.CROSS} 尚未配置账号或密码，请先在主菜单选择 [1] 进行配置！{T.RESET}")
        return

    domain_show = "@eLearning" if domain == "@study" else domain
    wifi_ssid = get_current_wifi_ssid()
    ssid_badge = f"{T.DIM}(当前无线: {T.WHITE}{wifi_ssid}{T.RESET}{T.DIM}){T.RESET} " if wifi_ssid else ""
    print(f"  {T.BOLD}发起认证请求: 用户名={username} [{domain_show}]{T.RESET} {ssid_badge}")
    render_spinner(f"正在探测网关 http://{host} (账号: {username} [{domain_show}])...", duration=0.6)

    client = LzuSrunClient(host=host, acid=acid)
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
    log_name = os.path.basename(LOG_FILE)
    print_subpage_header("SYSTEM LOGS | AUTHENTICATION RECORDS", "查看运行与认证日志", f"展示本地 {log_name} 最近 {lines} 条记录")
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

def prompt_config():
    """配置上网账号、密码与认证域名 (保存成功后自动拉起/重启后台守护服务)"""
    T = ClaudeTheme
    config = ConfigManager.load()
    cur_user = config.get("username", "")
    cur_enc_pwd = config.get("password_encrypted", "")
    cur_domain = config.get("domain", "@study")

    print_subpage_header(
        "CONFIGURATION | USER CREDENTIALS & DOMAIN",
        "配置上网账号与密码",
        "设置学号、密码与认证域名，数据采用 Windows DPAPI 用户账户安全保护"
    )

    # 1. 上网账号
    username = prompt_claude_input("上网账号/学号", default_val=cur_user)
    if not username:
        print(f"  {T.YELLOW}{T.CROSS} 账号不能为空，配置未保存。{T.RESET}")
        return

    # 2. 上网密码 (直接回车保留已保存密码)
    password = prompt_claude_password("上网密码", has_existing=bool(cur_enc_pwd))
    if password:
        encrypted_pwd = encrypt_password(password)
        if encrypted_pwd.startswith("b64:"):
            print(f"  {T.YELLOW}⚠ 注意: Windows DPAPI 加密不可用，本次密码降级为弱加密存储 (等同于明文)！{T.RESET}")
    else:
        encrypted_pwd = cur_enc_pwd
    if not encrypted_pwd:
        print(f"  {T.YELLOW}{T.CROSS} 密码不能为空，配置未保存。{T.RESET}")
        return

    # 3. 认证域名
    print(f"\n  {T.BOLD}请选择认证域名类型:{T.RESET}")
    print(f"    {T.ORANGE}1.{T.RESET} @eLearning    {T.DIM}(学生在线学习专网){T.RESET}")
    print(f"    {T.ORANGE}2.{T.RESET} @lzu.edu.cn   {T.DIM}(兰州大学校园网主域认证){T.RESET}")
    cur_choice = "1" if cur_domain == "@study" else "2"
    choice = prompt_claude_input("请选择认证域名 [1: @eLearning, 2: @lzu.edu.cn]", default_val=cur_choice)
    domain = "@lzu.edu.cn" if choice.strip() == "2" else "@study"

    # 4. 保存配置
    new_config = {
        "username": username,
        "password_encrypted": encrypted_pwd,
        "domain": domain,
        "host": config.get("host", "10.10.0.166"),
        "acid": config.get("acid", "2"),
        "check_interval": config.get("check_interval", 10)
    }
    if not ConfigManager.save(new_config):
        print(f"\n  {T.RED}{T.CROSS} 配置保存失败，请检查目录写入权限。{T.RESET}")
        return

    print(f"\n  {T.GREEN}{T.CHECK} 上网账号配置已安全保存！(Windows DPAPI 加密已保护){T.RESET}")
    logger.info(f"上网账号配置已更新 (用户: {username}, 域名: {domain})")

    # 5. 配置即守护: 保存后自动拉起/重启后台守护服务
    render_spinner("正在自动拉起后台守护服务...", duration=0.5)
    if get_daemon_pid():
        stop_daemon_process()
        time.sleep(0.3)
    ok, msg = start_daemon_process()
    if ok:
        print(f"  {T.GREEN}{T.CHECK} 后台守护服务已自动开启，将 24 小时静默监听断线重连。{T.RESET}")
    else:
        print(f"  {T.YELLOW}后台守护服务未能自动启动: {msg}{T.RESET}")

def wait_for_return():
    """二级页面通用返回控制: 按回车 / Backspace / Delete / ESC 返回上一级菜单"""
    T = ClaudeTheme
    print(f"\n  {T.DIM}按 Backspace (删除键) 或 回车键 返回上一级菜单...{T.RESET}")
    while True:
        k = get_menu_key()
        if k in ("ENTER", "BACKSPACE", "ESC", "DELETE"):
            break

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
                ("7", "清空历史运行日志", f"清除本地 {os.path.basename(LOG_FILE)} 文件"),
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
                elif k == 'q':
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
    cleanup_orphan_mei_dirs()
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
        host = config.get("host", "10.10.0.166")
        acid = config.get("acid", "2")
        if not username or not password:
            print("错误: 尚未配置账号或密码，请先使用 --config 进行配置。")
            sys.exit(1)
        client = LzuSrunClient(host=host, acid=acid)
        try:
            res = client.login(username, password, domain)
            print(res.get("msg", "登录请求已处理"))
            sys.exit(0 if res.get("success") else 1)
        except Exception as e:
            print(f"认证失败: 无法连接校园网认证网关 (http://{host})，请确认已连接 iLZU/LZU 校园网络。详情: {e}")
            sys.exit(1)
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