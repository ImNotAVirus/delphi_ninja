#!/usr/bin/env python
import re
from binaryninja import BinaryReader, BinaryView


cVmtSelfPtr             = -0x4C
cVmtIntfTable           = -0x48
cVmtAutoTable           = -0x44
cVmtInitTable           = -0x40
cVmtTypeInfo            = -0x3C
cVmtFieldTable          = -0x38
cVmtMethodTable         = -0x34
cVmtDynamicTable        = -0x30
cVmtClassName           = -0x2C
cVmtInstanceSize        = -0x28
cVmtParent              = -0x24
cVmtSafeCallException   = -0x20
cVmtAfterConstruction   = -0x1C
cVmtBeforeDestruction   = -0x18
cVmtDispatch            = -0x14
cVmtDefaultHandler      = -0x10
cVmtNewInstance         = -0x0C
cVmtFreeInstance        = -0x08
cVmtDestroy             = -0x04

MATCH_CLASS_NAME = re.compile(rb'^[\w.:]+$')


class ClassFinder(object):
    '''
    TODO: Doc
    '''

    def __init__(self, bv: BinaryView):
        self.bv = bv
        self.br = BinaryReader(bv)
        self.code_section = bv.sections['CODE']
        self.seek(0)


    def seek(self, offset: int):
        code_start = self.code_section.start
        self.br.seek(code_start + offset)


    def get_possible_vmt(self):
        address_size = self.bv.arch.address_size
        assert address_size == 4

        while self.br.offset <= self.code_section.end - address_size:
            begin = self.br.offset
            class_vmt = self.br.read32()
            if begin == class_vmt + cVmtSelfPtr:
                return class_vmt


class DelphiClass(object):
    '''
    TODO: Doc
    '''

    def __init__(self, bv: BinaryView, address: int):
        # 64 bits is currently not supported
        address_size = bv.arch.address_size
        assert address_size == 4

        self.vmt_address = address
        self.is_valid = False
        self.bv = bv
        self.br = BinaryReader(bv)
        self.code_section = bv.sections['CODE']
        self.class_name = ''
        self.instance_size = 0

        if not self._check_self_ptr():
            return

        if not self._parse_name():
            return

        if not self._parse_instance_size():
            return

        self.is_valid = True


    def __repr__(self):
        return str(self)


    def __str__(self):
        if not self.is_valid:
            return f'<InvalidClass address=0x{self.vmt_address:08X}>'
        return f'<{self.class_name} address=0x{self.vmt_address:08X} size=0x{self.instance_size:X}>'


    def is_valid(self):
        return self.is_valid


    ## Private functions

    def _check_self_ptr(self) -> bool:
        self_ptr_addy = self.vmt_address + cVmtSelfPtr

        if not self._isValidCodeAdr(self_ptr_addy):
            return False

        self.br.seek(self_ptr_addy)
        self_ptr = self.br.read32()

        return self_ptr == self.vmt_address


    def _parse_name(self) -> bool:
        name_addy = self.vmt_address + cVmtClassName

        if not self._isValidCodeAdr(name_addy):
            return False

        self.br.seek(name_addy)
        class_name_addr = self.br.read32()

        if not self._isValidCodeAdr(class_name_addr):
            return False

        self.br.seek(class_name_addr)
        name_len = self.br.read8()
        class_name = self.br.read(name_len)

        if MATCH_CLASS_NAME.match(class_name) is None:
            return False

        self.class_name = class_name.decode()
        return True


    def _parse_instance_size(self) -> bool:
        instance_size_addy = self.vmt_address + cVmtInstanceSize

        if not self._isValidCodeAdr(instance_size_addy):
            return False

        self.br.seek(instance_size_addy)
        self.instance_size = self.br.read32()

        return True


    def _isValidCodeAdr(self, addy: int, allow_null=False) -> bool:
        if addy == 0:
            return True
        return addy >= self.code_section.start and addy < self.code_section.end


    def _seek_to_code(self, offset: int):
        self.br.seek(self.code_section.start + offset)
