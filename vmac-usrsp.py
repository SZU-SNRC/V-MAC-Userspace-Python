'''
Doc: Introdction
This document defines a code to implement VMAC sender or receiver
'''
'''
DOC: Using VMAC sender
This receiver is a standard python executable. Simply compile and run
Eg: python vmac-usrsp.py user=p --> p signfies this is the sender/producer
'''
'''
DOC: Using VMAC receiver
This receiver is a standard pyhton executable. Simply compile and run
Eg: python vmac-usrsp.py user=c --> c signfies this is the receiver/consumer
'''
'''
DOC:Warning
In a standard test runm always run the sender before
you run the receiver as the sender waits for an interest from the receiver.
DO NOT use both -p -c arguments while running the code. Use either one.
'''
import threading
import numpy as np
import models
import time
import argparse
import pickle
import os
import socket
import struct
import pyroute2.netlink.nlsocket as nl
from pyroute2.netlink import nlmsg
import siphash

# defines  sender thread, used by pthread_create()
sendth = None
running2 = 0
total = 0
consumer = 0
producer = 0
times = 0
loss = 0.0
#时间戳
int_time = None  # use for record diff between interest package sending and data receiving
count = 0

# define
MY_PROTOCOL = 31

# frame types
VMAC_FC_INT = 0x00  # Interest frame
VMAC_FC_DATA = 0x01  # Data frame
VMAC_FC_ANN = 0x04  # Announcement frame
VMAC_FC_INJ = 0x05  # Injected frame

# netlink parameters
VMAC_USER = 0x1F  # netlink ID to communicate with V-MAC Kernel Module
MAX_PAYLOAD = 0x7D0  # 2KB max payload per-frame

# 定义一个全局类变量, 全局类变量不需要定义，直接使用类名便可
vmac_priv = models.VmacLibPriv()


#---------------------vmac usrsp.c---------------------
# struct vmac_lib_priv vmac_priv;
def getrix(rate: float):
    ret = 0
    for i in range(models.RATES_NUM):
        if models.rates[i].rate == rate:
            ret = models.rates[i].rix
    return ret


def recvvmac():
    while 1:
        # TODO: 每次应用程序应该接收多少字节MAX_PAYLOAD
        respone = vmac_priv.sock_fd.recv(MAX_PAYLOAD)
        #分解接收到的数据
        frame = models.VmacFrame()
        meta = models.MetaData()
        buffer = bytearray(vmac_priv.nlh2.len - 100)
        ctl = models.Control()
        type = ctl.type
        seq = ctl.seq
        enc = ctl.enc
        frame.buf = buffer
        frame.len = vmac_priv.nlh2.len - 100
        # TODO:这里的两个是什么意思？
        frame.interest_name = intname
        frame.name_len = intnamelen
        meta.type = type
        meta.seq = seq
        meta.enc = enc
        callbacktest(frame, meta)


def vmac_register():
    '''
    Register process with kernel module and create rx reception thread
    
    old func need a cb function as parameter

    '''
    keys = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf]
    vmac_priv.key = keys[:]
    vmac_priv.msgy[0] = 'a'
    # cb function
    vmac_priv.sock_fd = nl.NetlinkSocket(MY_PROTOCOL)
    vmac_priv.pid = os.getpid()
    vmac_priv.sock_fd.bind(0, vmac_priv.pid, async_cache=True)
    vmac_priv.nlh = models.MyNLMSG(len=size, pid=os.getpid(), flags=0, type=4)
    vmac_priv.nlh2 = models.MyNLMSG(len=MAX_PAYLOAD)
    # 创建线程 一定要存储在类变量里面吗
    vmac_priv.thread = threading.Thread(recvvmac)
    thread_id = vmac_priv.thread.ident
    os.sched_setscheduler(thread_id, os.SCHED_FIFO, None)
    vmac_priv.nlh.type = 255
    vmac_priv.digest64 = 0
    size = len(vmac_priv.msgy) + 100
    nlmsg_header_packed = vmac_priv.getNLMSGHeader()
    # 转换netlink消息头为byte数组，再加上数据体一起传输到vmac模块
    vmac_priv.sock_fd.sendto(nlmsg_header_packed + vmac_priv.msgy, (0, 0))


def send_vmac(frame: models.VmacFrame, meta: models.MetaData):
    '''
    sends a vmac frame to VMAC kernel module
    
    Parameters:
    frame - contains data and interest buffers with their lengths, respectively.
    meta - contains meta data to be passed to kernel (e.g., type of frame, rate, sequence if applicable)
    
    '''
    txc = models.Control()
    s = models.Hash()
    ratesh = getrix(meta.rate)
    # intest_name 是一个str必须要转换成byte
    vmac_priv.digest64 = siphash.SipHash_2_4(
        vmac_priv.key, bytes(frame.interest_name, 'utf-8')).digest()
    vmac_priv.nlh.type = meta.type
    meta.enc = vmac_priv.digest64
    txc.type = meta.type
    txc.enc = vmac_priv.digest64
    txc.seq = meta.seq
    txc.rate = ratesh

    # 先把control struct成字节数组 然后加上frame.buf
    txc_bytes = txc.getCtlByte()
    vmac_priv.nlh.len = frame.len + 100
    nlmsg_header_packed = vmac_priv.getNLMSGHeader()
    message_complete = nlmsg_header_packed + txc_bytes + bytes(frame.buf)
    vmac_priv.sock_fd.sendto(message_complete, (0, 0))


def vmac_send_interest():
    '''
    send interest packet
    Creates an interest frame and sends it. Run as python thread process

    Parameters:
        tid - thread ID.Thread id which is a automatically created when calling
    Returns:
        void
    '''
    global int_time
    global total
    dataname = "chat"
    name_len = len(dataname)
    buffer = "testBuffer"
    total = 0  # 为什么要定义成全局变量
    frame = models.VmacFrame
    meta = models.MetaData
    while 1:
        total = 0
        frame.buf = buffer
        frame.len = len(buffer)
        frame.interest_name = dataname
        frame.name_len = len(dataname)
        meta.type = VMAC_FC_INT
        meta.rate = 6.5
        # send_vmac(frame, meta)
        # get timestape and s and ms
        timestamp = time.time()
        s = int(timestamp)
        ns = int((timestamp - s) / 1e9)
        ms = ns / 1e6  # transform part of ns into ms
        if ms > 999:
            s += 1
            ms = 0
        int_time = s
        int_time += ns / 1e9
        print("Sent @ timestamp = ", time.time(), "{:d}.{:03d}".format(s, ms))
        time.sleep(10)


def vmac_send_data():
    '''
    vmac_send_data - VMAC producer
    Creates data frames and sends them to receivers. Run as python process

    Parameters:
    tid - Thread id which is a automatically created when calling phread_create. 
    In this case not run as a thread. Default value of 0 to be used 

    '''
    dataname = "chat"
    name_len = len(dataname)
    sel = "a"
    msgy = bytearray(1024)
    sel = b'a'
    msgy[:] = sel * 1024
    frame = models.VmacFrame(buf=msgy, len=len(msgy), name_len=name_len)
    meta = models.MetaData(type=VMAC_FC_DATA, rate=60.0)
    for i in range(50000):
        meta.seq = i
        send_vmac(frame, meta)

    running2 = 0


def callbacktest(frame, meta):
    '''
    recv_frame - VMAC recv frame function

    Parameters:
    frame - struct containing frame buffer, interestname (if available), and their lengths respectively.
    meta - The meta meta information about frame currently: type, seq, encoding, and rate

    '''
    global int_time
    global total
    global sendth
    type = meta.type
    enc = meta.enc
    seq = meta.seq
    buff = frame.buf
    len = frame.len
    interest_name_len = frame.name_len
    frame_size = 0.008928  #in megabits  1116 bytes after V-MAC and 802.11 headers
    waittime = 15  # 15 seconds waiting/sleep for all interests to come in

    # get timestape and s and ms
    timestamp = time.time()
    s = int(timestamp)
    ns = int((timestamp - s) / 1e9)
    ms = ns // int(1e6)  # transform part of ns into ms
    if ms > 999:
        s += 1
        ms = 0
    timediff = s
    timediff += ns / 1e9
    # timediff = timediff - int_time
    if type == VMAC_FC_INT and producer == 1 and running2 == 0:
        sendth = threading.Thread(target=vmac_send_data)
        sendth.start()
        print("type:%d and seq=%d and count=%d" % (type, seq, count))
        print("time: " + "{:d}.{:03d}".format(s, ms))
    elif type == VMAC_FC_DATA and consumer:
        total += 1
        loss = (float(50000 - total) / 50000) * float(100)
        goodput = (float)(total * frame_size) / (timediff - waittime)
        print("type:% | seq=%d | loss=%f | goodput=%f |T= %f\n", type, seq,
              loss, goodput, timediff - waittime)
        print("content = ", buff, "length = ", len)


def run_vmac(weare):
    '''
    Decides if sender or receiver

    Parameters:
    weare - 0 -> Sender 1 -> Receiver
    '''
    global producer
    global consumer
    choice = weare

    if choice == 0:
        print("We are producer")
        producer = 1
        # test start-----
        frame = models.VmacFrame('a', len('a'), 'chat', len('chat'))
        meta = models.MetaData(type=VMAC_FC_INT)
        callbacktest(frame, meta)

        #test end-----
    elif choice == 1:
        print("We are consumer")
        running2 = 1
        producer = 0
        consumer = 1
        consumerth = threading.Thread(target=vmac_send_interest)
        consumerth.start()


if __name__ == '__main__':
    '''
    main -Main function

    Function register, call run_vmac

    Parameters:
    user - p or c 
    '''
    parser = argparse.ArgumentParser(description='vmac starting')
    parser.add_argument('-u',
                        '--user',
                        default='p',
                        help='producer or consumer')
    args = parser.parse_args()
    weare = 0
    # vmac_register(callbacktest)
    if args.user == 'p':
        weare = 0
    else:
        weare = 1
    run_vmac(weare)
    while 1:
        time.sleep(1)