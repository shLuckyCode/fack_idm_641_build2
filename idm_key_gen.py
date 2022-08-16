#!/usr/bin/env python
# -*- encoding: utf-8 -*-
'''
@File    :   idm_key_gen.py
@Time    :   2022/06/15 13:09:28
<<<<<<< HEAD
@Author  :   smaill
=======
@Author  :   smile
>>>>>>> 995ad5f2451eaee4a6a808686069fb9aa8a10265
@Contact :   smaill0702@gmail.com
@        :   pip install pycryptodome 
             pip install wmi 
             pip install pywin32
'''

from winreg import *
from Crypto.Cipher import ARC2
from shutil import copyfile
import math, win32api,os
#import pefile

key_table = '2YOPB3AQCVUXMNRS97WE0IZD4KLFGHJ8165T'
MData_key = b'58BE20ast4si5ls2D13'

ENCRYPT_MODE = 0
DECRYPT_MODE = 1

#username = 'smaill'.upper()
seed = 1234567

def calc_Serial(value):
    Serial = ''
    base = value

    for i in range(5):
        for n in range(36):
            if (base - n) % 37 == 0:
                base = (base - n) // 37
                Serial += key_table[n]
                break

    return Serial[::-1]

def QueryValue(subkey, name):
    value = None
    type = None
    
    key = OpenKey(HKEY_CURRENT_USER, subkey)
    if key:
        value, type = QueryValueEx(key, name)
    return value, type

def set_MData(DATA):
    sub_key = r"Software\\Classes\\WOW6432Node\\CLSID\\{79873CC5-3951-43ED-BDF9-D8759474B6FD}"
    try:
        key = OpenKey(HKEY_CURRENT_USER, sub_key, 0, KEY_SET_VALUE)
    except FileNotFoundError:
        key = CreateKeyEx(HKEY_CURRENT_USER, sub_key, 0, KEY_SET_VALUE)

    if DATA is None:
        raise TypeError('DATA cannot is None')
    elif isinstance(DATA, bytes):    
        SetValueEx(key, "MData", 1, REG_NONE, DATA)
    else:
        raise TypeError('cannot write {} to registry'.format(type(DATA)))

#typt:int 0->加密 1-> 解密
def ecrypt_RC2(data, key, typt = ENCRYPT_MODE):
    ecrypt_data = None
    cipher = ARC2.new(key, ARC2.MODE_ECB, )

    if typt == 0:#加密数据 
        ecrypt_data = cipher.encrypt(data)
    elif typt == 1:#解密数据     
        ecrypt_data = cipher.decrypt(data)
    else:
        pass

    return ecrypt_data

def check_code(file, offset, origin_code,rSize):
    file.seek(offset)
    buff = file.read(rSize)
    if buff == origin_code:
        return True
    
    return False


def patch_code(file, offset, patch_code):
    file.seek(offset)
    return file.write(patch_code)


def fack_IDM():
    #image base = 0x400000
    offset_14B3 = 0x8BD72
    offset_14B5 = 0x8BE2C
    offset_14D4 = 0x8E6CD
    offset_14BF = 0x8CC5F
    offset_14C2 = 0x8BEAA #
    offset_14EB = 0x8CC7E
    
    orgin_14B3 = b"\xE8\xA6\x64\x16\x00"
    orgin_14B5 = b"\xE8\xEC\x63\x16\x00"
    orgin_14D4 = b"\x74\x26"
    orgin_14BF = b"\xE8\xB9\x55\x16\x00"
    orgin_14C2 = b"\x0F\x84\xFF\xE6\xFF\xFF"
    orgin_14EB = b"\xE8\x9A\x55\x16\x00"
    

    patch_code = b"\x90\x90\x90\x90\x90"
    patch_14C2 = b"\xE9\x00\xE7\xFF\xFF\x90"
    patch_14D4 = b"\xEB\x26"
    
    sub_key = r"SOFTWARE\\DownloadManager"
    idm_path, type = QueryValue(sub_key, "ExePath")
    if idm_path is None:
        print("install IDM?\n")
        
    print("[+] found IDM in regedit: {0}".format(idm_path))
    
    if os.path.exists(idm_path):
        idm_path_bak = idm_path + "_bak"
        copyfile(idm_path, idm_path_bak)
        print("[+] bak IDM to: {0}".format(idm_path_bak))
    try:
        f = open(idm_path, 'rb+')
        
        #check file
        if False == check_code(f,  offset_14B3, orgin_14B3, 5) or \
            False == check_code(f, offset_14B5, orgin_14B5, 5) or \
            False == check_code(f, offset_14D4, orgin_14D4, 2) or \
            False == check_code(f, offset_14BF, orgin_14BF, 5) or \
            False == check_code(f, offset_14C2, orgin_14C2, 6) or \
            False == check_code(f, offset_14EB, orgin_14EB, 5):
                raise Exception("already patched or version not match!") 
        
        #patch file
        patch_code(f, offset_14B3, patch_code)
        patch_code(f, offset_14B5, patch_code)
        patch_code(f, offset_14D4, patch_14D4)
        patch_code(f, offset_14BF, patch_code)
        patch_code(f, offset_14C2, patch_14C2)
        patch_code(f, offset_14EB, patch_code)
        f.flush()  
        f.close()
    except FileNotFoundError:
        print ("{0} is not found.".format(idm_path))
    except PermissionError:
        print ("You don't have permission to access {0}".format(idm_path))
        
        
    '''
    pe=pefile.PE(idm_path)
   
    #patch 0x14B3 and 0x14B5(FACK Serial Number)
    #rva = pe.get_rva_from_offset(offset_14B3)
    pe.set_bytes_at_offset(offset_14B3, patch_14B3)
    pe.set_bytes_at_offset(offset_14B5, patch_14B5)
    pe.set_bytes_at_offset(offset_14D4, patch_14D4)
    pe.set_bytes_at_offset(offset_14BF, patch_14BF)
    pe.write()
    print(idm_path)
    '''    

    
def main():
    encrypt_MData = ''
    global seed

    username = input('input your name: ').upper()
    for c in username:
        seed += ord(c)

    key1 = seed * 43
    key2 = seed * 23
    key3 = seed * 17
    key4 = seed * 53

    serial1 = calc_Serial(key1)
    serial2 = calc_Serial(key2)
    serial3 = calc_Serial(key3)
    serial4 = calc_Serial(key4)

    sn = f'{serial1}-{serial2}-{serial3}-{serial4}'

    print(f'[+] sn: {sn}')

    in_str = input("使用生成的序列号注册程序，并等待程序关闭后输入 'g' 继续: ")
    if in_str != 'g':
        return

    #patch MData 校验
    b_sn = bytes(sn, encoding='UTF-8')
    #rc2 MODE_ECB模式需要被加密数据16字节对齐
    b_sn += b'\x00' * (16 - len(b_sn) % 16)
     
    encrypt_MData = ecrypt_RC2(b_sn, MData_key, ENCRYPT_MODE)
    if encrypt_MData:
        set_MData(encrypt_MData)

    #patch 程序暗桩
    fack_IDM()
    print('[+] patch over!')


main()



'''
def get_CLSID1(VolumeSerialNumber='6F41C61B',sn='GMSDY'):
    sum = 1
    for i in sn:
        sum = 7 * sum + 2 * ord(i)

    sum += int(VolumeSerialNumber,16)
    v5 = 1.33
    clsid = VolumeSerialNumber.lower()
    
    while(len(clsid) < 0x20):
        tmp = sum * v5
        v5 += 0.27
        clsid += "%lx"%(math.trunc(tmp)&0xFFFFFFFF)

    clsid = list(clsid[:32])
    clsid.insert(12,'-')
    clsid.insert(17,'-')
    clsid.insert(22,'-')
    clsid.insert(27,'-')

    print("".join(clsid[::-1]))

def get_CLSID2(VolumeSerialNumber,sn):
    sum = 1
    for i in sn:
        sum = 5 * sum + 2 * ord(i)
    sum += int(VolumeSerialNumber,16)
    sum = math.trunc(sum/3)
    v5 = 1.55
    clsid = ''
    while(len(clsid) < 0x20):
        sum = math.trunc(sum * v5)&0xFFFFFFFF
        v5 += 0.25
        clsid += "%lx"%(sum)
    clsid = list(clsid[:32])
    clsid.insert(8,'-')
    clsid.insert(13,'-')
    clsid.insert(18,'-')
    clsid.insert(23,'-')
    print("".join(clsid))
    
    def get_VolumeSerialNumber():
    return win32api.GetVolumeInformation("C:\\")[1]
'''

"""
get_CLSID1('6F41C61B', 'GMSDY-S3')
get_CLSID2('6F41C61B', 'GMSDY-S3')
#get_VolumeSerialNumber()

#build_CLSID()
#main()
print(get_VolumeSerialNumber())
enc_str = b'Nr{ij|oxA^q|nnxnA^QNTYAf8n`'
newstr = ''
for i in range(len(enc_str)):
    c = enc_str[i]
    tmp = c ^ 0x1D
    newstr += chr(tmp)
print(newstr)
"""

