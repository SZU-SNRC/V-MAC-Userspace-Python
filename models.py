import numpy as np
import threading
import struct
import pyroute2.netlink.nlsocket as nl
# Defines
RATES_NUM = 44
SGI = 0x40
HT40 = 0x80


class MyNLMSG:

    def __init__(self, len=0, pid=0, flags=0, type=0, seq=0) -> None:
        self.len = len
        self.pid = pid
        self.flags = flags
        self.type = type
        self.seq = seq


class RateStruct:

    def __init__(self, rate, rix):
        self.rate = rate
        self.rix = rix


rates = [
    RateStruct(1.0, 0),
    RateStruct(2.0, 1),
    RateStruct(5.5, 2),
    RateStruct(6.0, 4),
    RateStruct(9.0, 5),
    RateStruct(10.0, 7),
    RateStruct(11.0, 3),
    RateStruct(12.0, 6),
    RateStruct(18.0, 8),
    RateStruct(36.0, 9),
    RateStruct(48.0, 10),
    RateStruct(54.0, 11),
    RateStruct(6.5, 12),
    RateStruct(13.0, 13),
    RateStruct(19.5, 14),
    RateStruct(26.0, 15),
    RateStruct(39.0, 16),
    RateStruct(52.0, 18),
    RateStruct(58.5, 20),
    RateStruct(65.0, 22),
    RateStruct(13.5, 12 + HT40),
    RateStruct(27.0, 13 + HT40),
    RateStruct(40.5, 14 + HT40),
    RateStruct(54.0, 15 + HT40),
    RateStruct(81.0, 16 + HT40),
    RateStruct(108.0, 19 + HT40),
    RateStruct(121.5, 20 + HT40),
    RateStruct(135.0, 22 + HT40),
    RateStruct(7.2, 12 + SGI),
    RateStruct(14.4, 13 + SGI),
    RateStruct(21.7, 14 + SGI),
    RateStruct(28.9, 15 + SGI),
    RateStruct(43.3, 16 + SGI),
    RateStruct(57.8, 18 + SGI),
    RateStruct(65.0, 20 + SGI),
    RateStruct(72.2, 22 + SGI),
    RateStruct(15.0, 12 + HT40 + SGI),
    RateStruct(30.0, 13 + HT40 + SGI),
    RateStruct(45.0, 14 + HT40 + SGI),
    RateStruct(60.0, 15 + HT40 + SGI),
    RateStruct(90.0, 16 + HT40 + SGI),
    RateStruct(120.0, 18 + HT40 + SGI),
    RateStruct(135.0, 20 + HT40 + SGI),
    RateStruct(150.0, 22 + HT40 + SGI),
]


class VmacFrame:

    def __init__(self,
                 buf='a',
                 len=0,
                 interest_name='chat',
                 name_len=0) -> None:
        self.buf = buf
        self.len = np.uint16(len)
        self.interest_name = interest_name
        self.name_len = np.uint16(name_len)


class MetaData:

    def __init__(self, type=0, seq=0, rate=0, enc=0) -> None:
        self.type = np.uint8(type)
        self.seq = np.uint16(seq)
        self.rate = float(rate)
        self.enc = np.uint64(enc)


class Control:

    def __init__(
        self,
        type=None,
        rate=None,
        enc=None,
        seq=None,
        bwsg=None,
        rate_idx=None,
        signal=None,
    ) -> None:
        self.type = type
        self.rate = rate
        self.enc = enc
        self.seq = seq
        self.bwsg = bwsg
        self.rate_idx = rate_idx
        self.signal = signal

    def getCtlByte(self):
        ctl_format = '1s 2s 1s 8s'
        ctl_packed = struct.pack(ctl_format, self.type, self.seq, self.rate,
                                 self.enc)
        return ctl_packed


class Hash:

    def __init__(self, id=None, name=None, hh=None) -> None:
        self.id = id
        self.name = name


class VmacLibPriv:

    def __init__(self,
                 names=None,
                 src_addr=None,
                 dest_addr=None,
                 pid=None,
                 nlh=MyNLMSG(),
                 iov=None,
                 msg=None,
                 nlh2=None,
                 iov2=None,
                 msg2=None,
                 digest64=0,
                 fixed_rate=0,
                 cb=None,
                 msgy=bytearray(2000),
                 sock_fd=nl.NetlinkSocket(),
                 thread=None,
                 key=bytearray(16)) -> None:
        self.names = names  # hash之后的名字
        self.src_addr = src_addr
        self.dest_addr = dest_addr
        self.nlh = nlh
        self.iov = iov
        self.msg = msg
        self.nlh2 = nlh2
        self.iov2 = iov2
        self.msg2 = msg2
        self.digest64 = digest64
        self.fixed_rate = fixed_rate
        self.cb = cb
        self.msgy = msgy
        self.sock_fd = sock_fd
        self.thread = thread
        self.key = key

    # 写一个set函数传递参数

    # 将数据转换为byte数组
    def getNLMSGHeader(self):
        nlmsg_header_format = 'IHHII'
        msg_len = self.nlh.len
        msg_type = self.nlh.type
        msg_pid = self.nlh.pid
        msg_flags = self.nlh.flags
        msg_seq = self.nlh.seq
        total_length = msg_len + 16
        nlmsg_header_packed = struct.pack(nlmsg_header_format, total_length,
                                          msg_type, msg_flags, msg_seq,
                                          msg_pid)
        return nlmsg_header_packed


class PackageInfo:

    def __init__(self, pack_num) -> None:
        self.pack_num = np.uint16(pack_num)
