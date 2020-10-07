#!/usr/bin/env python
import re
import copy
from binaryninja import BinaryReader, BinaryView, LogLevel
from typing import Mapping, Union

from ..constants import VMTOffsets
from ..bnlogger import BNLogger


MATCH_CLASS_NAME = re.compile(rb'^[\w.:]+$')


class DelphiVMT(object):
    '''
    TODO: Doc
    '''

    def __init__(self, bv: BinaryView, delphi_version: int, address: int, offset_size = -1,
            analyzer = None):
        self._offset_size = offset_size if offset_size > 0 else bv.address_size
        self._vmt_address = address
        self._is_valid = False
        self._bv = bv
        self._br = BinaryReader(bv)
        self._code_section = bv.sections['CODE']
        self._vmt_offsets = VMTOffsets(delphi_version, self._offset_size)
        self._class_name = ''
        self._instance_size = 0
        self._parent_vmt = 0
        self._table_list: Mapping[int, str] = {}
        self._virtual_methods: Mapping[int, str] = {}

        if not self._check_self_ptr():
            return

        if not self._resolve_name():
            return

        if not self._resolve_instance_size():
            return

        if not self._resolve_parent_vmt():
            return

        if not self._resolve_table_list():
            return

        if not self._resolve_virtual_methods():
            return

        self._is_valid = True


    def __repr__(self):
        return str(self)


    def __str__(self):
        if not self._is_valid:
            return f'<InvalidVmt address=0x{self._vmt_address:08X}>'

        return (f'<{self._class_name} start=0x{self.start:08X} '
            f'instance_size=0x{self._instance_size:X}>')


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
    def table_list(self) -> Mapping[int, str]:
        return self._table_list

    @property
    def virtual_methods(self) -> Mapping[int, str]:
        return self._virtual_methods

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

    @property
    def br_offset(self) -> int:
        return self._br.offset


    ## Public API

    def seek_to_code(self, address: int) -> bool:
        if not self._is_valid_code_addr(address):
            return False

        self._br.seek(address)
        return True


    def seek_to_code_offset(self, offset: int) -> bool:
        if not self._is_valid_code_addr(self._code_section.start + offset):
            return False

        self._br.seek(self._code_section.start + offset)
        return True


    def seek_to_vmt_offset(self, offset: int) -> bool:
        if not self._is_valid_code_addr(self._vmt_address + offset):
            return False

        self._br.seek(self._vmt_address + offset)
        return True


    def read8(self) -> Union[None, int]:
        return self._br.read8()


    def read32(self) -> Union[None, int]:
        return self._br.read32()


    def read_ptr(self) -> Union[None, int]:
        if self._offset_size == 4:
            return self._br.read32()
        elif self._offset_size == 8:
            return self._br.read64()


    ## Protected methods

    def _check_self_ptr(self) -> bool:
        if not self.seek_to_vmt_offset(self._vmt_offsets.cVmtSelfPtr):
            return False

        self_ptr = self.read_ptr()
        return self_ptr == self._vmt_address


    def _resolve_name(self) -> bool:
        class_name_addr = self._get_class_name_addr()

        if class_name_addr is None:
            return False

        self._br.seek(class_name_addr)
        name_len = self._br.read8()

        if name_len == 0:
            BNLogger.log(
                f'Care, VMT without name (len: 0) detected at 0x{self._vmt_address:08X}',
                LogLevel.WarningLog
            )

        class_name = self._br.read(name_len)

        if MATCH_CLASS_NAME.match(class_name) is None:
            return False

        self._class_name = class_name.decode()
        return True


    def _resolve_instance_size(self) -> bool:
        if not self.seek_to_vmt_offset(self._vmt_offsets.cVmtInstanceSize):
            return False

        self._instance_size = self.read_ptr()
        return True


    def _resolve_parent_vmt(self) -> bool:
        if not self.seek_to_vmt_offset(self._vmt_offsets.cVmtParent):
            return False

        self._parent_vmt = self.read_ptr()
        return True


    def _resolve_virtual_methods(self) -> bool:
        class_name_addr = self._get_class_name_addr()

        if class_name_addr is None:
            return False

        address_size = self._bv.address_size
        offsets = self.vmt_offsets.__dict__.items()
        offset_map = {y:x for x, y in offsets}
        tables_addr = self._table_list.keys()

        if not self.seek_to_vmt_offset(self._vmt_offsets.cVmtParent + address_size):
            return False

        while self._br.offset < class_name_addr and self._br.offset not in tables_addr:
            field_value = self.read_ptr()

            if field_value == 0:
                continue

            if not self._is_valid_code_addr(field_value):
                prev_offset = self._br.offset - address_size
                raise RuntimeError(f'Invalid code address deteted at 0x{prev_offset:08X} '
                    '({self.class_name})\n If you think it\'s a bug, please open an issue on '
                    'Github with the used binary or the full VMT (fields + VMT) as an attachment')

            field_offset = self._br.offset - self._vmt_address - address_size

            if field_offset in offset_map:
                # Remove `cVmt` prefix
                method_name = f'{self.class_name}.{offset_map[field_offset][4:]}'
            else:
                method_name = f'{self.class_name}.sub_{field_value:x}'

            self._virtual_methods[field_value] = method_name

        return True


    def _resolve_table_list(self) -> bool:
        if not self.seek_to_vmt_offset(self.vmt_offsets.cVmtIntfTable):
            return False

        offsets = self._vmt_offsets.__dict__.items()
        offset_map = {y:x[4:] for x, y in offsets}

        stop_at = self._vmt_address + self._vmt_offsets.cVmtClassName

        while self._br.offset != stop_at:
            prev_br_offset = self._br.offset
            address = self.read_ptr()

            if address < 1:
                continue

            if not self._is_valid_code_addr(address):
                raise RuntimeError('Invalid table address detected')

            self._table_list[address] = offset_map[prev_br_offset - self._vmt_address]

        return True


    def _is_valid_code_addr(self, addy: int, allow_null=False) -> bool:
        if addy == 0:
            return allow_null
        return addy >= self._code_section.start and addy < self._code_section.end


    def _get_class_name_addr(self) -> Union[None, int]:
        if not self.seek_to_vmt_offset(self._vmt_offsets.cVmtClassName):
            return None

        class_name_addr = self.read_ptr()

        if not self._is_valid_code_addr(class_name_addr):
            return None

        return class_name_addr
