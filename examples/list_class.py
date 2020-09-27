#!/usr/bin/env python
import os, sys
from binaryninja import BinaryView, BinaryViewType

sys.path.insert(0, os.path.pardir)
from delphi_analyser import ClassFinder, DelphiClass
from bnlogger import BNLogger


def main(target: str, delphi_version: int):
    # Just disable some features for large binaries
    opts = {
        'analysis.mode': 'controlFlow',
        'analysis.linearSweep.autorun': False,
        'analysis.linearSweep.controlFlowGraph': False,
    }

    bv = BinaryViewType.get_view_of_file_with_options(target, options=opts)

    if bv is None:
        print(f'Invalid binary path: {target}')
        exit(-1)

    bv.update_analysis_and_wait()

    BNLogger.init_console()
    BNLogger.log('File loaded')
    BNLogger.log('-----------------------------')
    BNLogger.log('Searching for VMT...')

    finder = ClassFinder(bv, delphi_version)
    addy = finder.get_possible_vmt()

    while addy:
        BNLogger.log(DelphiClass(bv, delphi_version, addy))
        addy = finder.get_possible_vmt()


if __name__ == '__main__':
    if len(sys.argv) != 3:
        print(f'Usage: {sys.argv[0]} <file_name> <delphi_version>')
        exit(-1)

    main(sys.argv[1], int(sys.argv[2]))
