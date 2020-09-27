#!/usr/bin/env python
import re
from binaryninja import BinaryReader, BinaryView

from constants import VMTOffsets


MATCH_CLASS_NAME = re.compile(rb'^[\w.:]+$')


class ClassFinder(object):
    '''
    TODO: Doc
    '''

    def __init__(self, bv: BinaryView, delphi_version: int):
        self._bv = bv
        self._br = BinaryReader(bv)
        self._code_section = bv.sections['CODE']
        self._vmt_offsets = VMTOffsets(delphi_version)
        self.seek_to_code(0)


    def seek_to_code(self, offset: int):
        self._br.seek(self._code_section.start + offset)


    def get_possible_vmt(self):
        address_size = self._bv.arch.address_size
        assert address_size == 4

        while self._br.offset <= self._code_section.end - address_size:
            begin = self._br.offset
            class_vmt = self._br.read32()
            if begin == class_vmt + self._vmt_offsets.cVmtSelfPtr:
                return class_vmt


class DelphiClass(object):
    '''
    TODO: Doc
    '''

    def __init__(self, bv: BinaryView, delphi_version: int, address: int):
        # 64 bits is currently not supported
        address_size = bv.arch.address_size
        assert address_size == 4

        self._vmt_address = address
        self._is_valid = False
        self._bv = bv
        self._br = BinaryReader(bv)
        self._code_section = bv.sections['CODE']
        self._vmt_offsets = VMTOffsets(delphi_version)
        self._class_name = ''
        self._instance_size = 0
        self._parent_vmt = 0

        if not self._check_self_ptr():
            return

        if not self._parse_name():
            return

        if not self._parse_instance_size():
            return

        if not self._parse_parent_vmt():
            return

        self._is_valid = True


    def __repr__(self):
        return str(self)


    def __str__(self):
        if not self._is_valid:
            return f'<InvalidClass address=0x{self._vmt_address:08X}>'
        return f'<{self._class_name} address=0x{self._vmt_address:08X} size=0x{self._instance_size:X}>'

    ## Properties

    @property
    def vmt_address(self):
        return self._vmt_address

    @property
    def is_valid(self):
        return self._is_valid

    @property
    def class_name(self):
        return self._class_name

    @property
    def instance_size(self):
        return self._instance_size

    @property
    def parent_vmt(self):
        return self._parent_vmt

    @property
    def start(self):
        return self._vmt_address + self._vmt_offsets.cVmtSelfPtr


    ## Private functions

    def _check_self_ptr(self) -> bool:
        self_ptr_addy = self._vmt_address + self._vmt_offsets.cVmtSelfPtr

        if not self._isValidCodeAdr(self_ptr_addy):
            return False

        self._br.seek(self_ptr_addy)
        self_ptr = self._br.read32()

        return self_ptr == self._vmt_address


    def _parse_name(self) -> bool:
        name_addy = self._vmt_address + self._vmt_offsets.cVmtClassName

        if not self._isValidCodeAdr(name_addy):
            return False

        self._br.seek(name_addy)
        class_name_addr = self._br.read32()

        if not self._isValidCodeAdr(class_name_addr):
            return False

        self._br.seek(class_name_addr)
        name_len = self._br.read8()
        class_name = self._br.read(name_len)

        if MATCH_CLASS_NAME.match(class_name) is None:
            return False

        self._class_name = class_name.decode()
        return True


    def _parse_instance_size(self) -> bool:
        instance_size_addy = self._vmt_address + self._vmt_offsets.cVmtInstanceSize

        if not self._isValidCodeAdr(instance_size_addy):
            return False

        self._br.seek(instance_size_addy)
        self._instance_size = self._br.read32()

        return True


    def _parse_parent_vmt(self) -> bool:
        parent_vmt_addy = self._vmt_address + self._vmt_offsets.cVmtParent

        if not self._isValidCodeAdr(parent_vmt_addy, True):
            return False

        self._br.seek(parent_vmt_addy)
        self._parent_vmt = self._br.read32()

        return True


    def _isValidCodeAdr(self, addy: int, allow_null=False) -> bool:
        if addy == 0:
            return True
        return addy >= self._code_section.start and addy < self._code_section.end


    def _seek_to_code(self, offset: int):
        self._br.seek(self._code_section.start + offset)
