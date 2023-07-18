#!/usr/bin/env python3

import click
import ecdsa
import hashlib
import zipfile
from dfu import dfu_cc_pb2 as pb

@click.command()
@click.argument("bootloader", type = click.File("rb"))
@click.argument("package", type = click.Path(exists = True))
def find_pk(bootloader, package):
    pkt = pb.Packet()
    with zipfile.ZipFile(package, "r") as zf:
        for e in zf.infolist():
            if e.filename.endswith(".dat"):
                pkt.ParseFromString(zf.read(e.filename))
    xmsg = pkt.signed_command.command.init.SerializeToString()
    s = pkt.signed_command.signature
    xsgn = s[31::-1] + s[63:31:-1]
    dump = bootloader.read()
    for idx in range(len(dump)-64):
        b1 = dump[idx:][:64]
        b2 = b1[31::-1] + b1[63:31:-1]
        try:
            vk = ecdsa.VerifyingKey.from_string(
                b2,
                curve=ecdsa.NIST256p,
                hashfunc=hashlib.sha256)
            vk.verify(xsgn, xmsg)
            print(f"Found valid PK at offset 0x{idx:08x}")
        except ecdsa.errors.MalformedPointError:
            pass
        except ecdsa.keys.BadSignatureError:
            pass
