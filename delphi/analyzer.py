from binaryninja import BinaryReader, BinaryView
from typing import Callable, List, Union
import copy

from .vmt import DelphiVMT
from .constants import VMTOffsets


class DelphiAnalyzer(object):
    '''
    TODO: Doc
    '''

    def __init__(self, bv: BinaryView, delphi_version: int, offset_ptr_size = -1, start = -1, end = -1):
        self._offset_ptr_size = offset_ptr_size if offset_ptr_size > 0 else bv.address_size
        self._start = start if start >= 0 else bv.start
        self._end = end if end > 0 else bv.end
        self._vmt_list: List[DelphiVMT] = []
        self._bv = bv
        self._br = BinaryReader(bv)
        self._delphi_version = delphi_version
        self._vmt_offsets = VMTOffsets(delphi_version, self._offset_ptr_size)

        # Not really sure about this but it's working on my test binary (Win64 Delphi v10.3)
        # Need to check offsets for macOS
        # I'll clean that later
        if self._bv.view_type == 'PE' and self._offset_ptr_size == 8:
            for x, y in self._vmt_offsets.__dict__.items():
                setattr(self._vmt_offsets, x, y + -24)


    ## Properties

    @property
    def start(self) -> int:
        return self._start

    @property
    def end(self) -> int:
        return self._end

    @property
    def delphi_version(self) -> int:
        return self._delphi_version

    @property
    def vmt_list(self) -> List[DelphiVMT]:
        return self._vmt_list

    @property
    def vmt_offsets(self) -> VMTOffsets:
        return copy.copy(self._vmt_offsets)


    ## Public API

    def update_analysis_and_wait(self, callback: Callable[[DelphiVMT], None] = None):
        self._vmt_list = []
        self._seek_to_offset(0)

        while True:
            addy = self._get_possible_vmt()

            if addy is None:
                break

            delphi_vmt = DelphiVMT(self._bv, self._delphi_version, addy, self, self._offset_ptr_size)

            if not delphi_vmt.is_valid:
                continue

            self._vmt_list.append(delphi_vmt)

            if callback is not None:
                callback(delphi_vmt)


    ## Protected methods

    def _seek_to_offset(self, offset: int):
        self._br.seek(self._start + offset)


    def _read_ptr(self) -> Union[None, int]:
        if self._offset_ptr_size == 4:
            return self._br.read32()
        elif self._offset_ptr_size == 8:
            return self._br.read64()


    def _get_possible_vmt(self) -> int:
        while self._br.offset <= self._end - self._offset_ptr_size - 1:
            begin = self._br.offset

            if not self._bv.is_valid_offset(begin):
                self._br.seek_relative(self._offset_ptr_size)
                continue

            class_vmt = self._read_ptr()

            if class_vmt is None:
                # If BinaryReader can't read, it will not update the offset
                self._br.seek_relative(self._offset_ptr_size)
                continue

            if begin == class_vmt + self._vmt_offsets.cVmtSelfPtr:
                return class_vmt
