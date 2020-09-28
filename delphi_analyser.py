#!/usr/bin/env python
import re
import copy
from binaryninja import BinaryReader, BinaryView
from typing import List, Union

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


    def get_possible_vmt(self) -> int:
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
        self._methods: List[int] = []

        if not self._check_self_ptr():
            return

        if not self._parse_name():
            return

        if not self._parse_instance_size():
            return

        if not self._parse_parent_vmt():
            return

        if not self._parse_methods():
            return

        self._is_valid = True


    def __repr__(self):
        return str(self)


    def __str__(self):
        if not self._is_valid:
            return f'<InvalidVmt address=0x{self._vmt_address:08X}>'
        return f'<{self._class_name} start=0x{self.start:08X} size=0x{self._instance_size:X}>'


    ## Properties

    @property
    def vmt_address(self) -> int:
        return self._vmt_address

    @property
    def is_valid(self) -> bool:
        return self._is_valid

    @property
    def class_name(self) -> str:
        return self._class_name

    @property
    def instance_size(self) -> int:
        return self._instance_size

    @property
    def parent_vmt(self) -> int:
        return self._parent_vmt

    @property
    def vmt_offsets(self) -> VMTOffsets:
        return copy.copy(self._vmt_offsets)

    @property
    def start(self) -> int:
        return self._vmt_address + self._vmt_offsets.cVmtSelfPtr

    @property
    def size(self) -> int:
        end = 0 # ????
        return end - self.start


    ## Public API

    def read32(self, offset: int) -> Union[None, int]:
        if not self._is_valid:
            return

        self._br.seek(self._vmt_address + offset)
        return self._br.read32()

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


    def _parse_methods(self) -> bool:
        return True


    def _isValidCodeAdr(self, addy: int, allow_null=False) -> bool:
        if addy == 0:
            return True
        return addy >= self._code_section.start and addy < self._code_section.end


    def _seek_to_code(self, offset: int):
        self._br.seek(self._code_section.start + offset)
