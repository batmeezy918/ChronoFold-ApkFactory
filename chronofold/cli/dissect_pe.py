#!/usr/bin/env python3
import argparse
import json
import pathlib
import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("exe")
    ap.add_argument("-o","--output",required=True)
    ap.add_argument("--bytes",type=int,default=256)
    a=ap.parse_args()
    p=pathlib.Path(a.exe)
    pe=pefile.PE(str(p),fast_load=False)
    ep_rva=pe.OPTIONAL_HEADER.AddressOfEntryPoint
    ep_file=pe.get_offset_from_rva(ep_rva)
    code=pe.__data__[ep_file:ep_file+a.bytes]
    md=Cs(CS_ARCH_X86,CS_MODE_32)
    ins=[]
    for i in md.disasm(code,pe.OPTIONAL_HEADER.ImageBase+ep_rva):
        ins.append({"address":hex(i.address),"bytes":i.bytes.hex(),"mnemonic":i.mnemonic,"op_str":i.op_str})
    result={
      "schema":"cf-dissection/pe-x86-v0.1",
      "entrypoint":{"rva":hex(ep_rva),"file_offset":hex(ep_file),
                    "virtual_address":hex(pe.OPTIONAL_HEADER.ImageBase+ep_rva)},
      "instruction_count":len(ins),
      "instructions":ins
    }
    out=pathlib.Path(a.output)
    out.parent.mkdir(parents=True,exist_ok=True)
    out.write_text(json.dumps(result,indent=2)+"\n")
    print(json.dumps(result,indent=2))
if __name__=="__main__":
    main()
