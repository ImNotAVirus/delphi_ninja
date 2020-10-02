#!/usr/bin/env python
from binaryninja import BinaryViewType

import importlib
import sys
from os import path

# from delphi_ninja.bnlogger import BNLogger
# from delphi_ninja.delphi_analyser import ClassFinder

module_dir = path.dirname(path.dirname(path.abspath(__file__)))
module_name = path.basename(module_dir)
module_parent = path.dirname(module_dir)
sys.path.insert(0, module_parent)
delphi_ninja = importlib.import_module(module_name)
BNLogger = delphi_ninja.bnlogger.BNLogger
ClassFinder = delphi_ninja.delphi_analyser.ClassFinder


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

    BNLogger.init_console()
    BNLogger.log('File loaded')
    BNLogger.log('-----------------------------')
    BNLogger.log('Searching for VMT...')

    finder = ClassFinder(bv, delphi_version)
    finder.update_analysis_and_wait(lambda vmt: BNLogger.log(vmt))


if __name__ == '__main__':
    if len(sys.argv) != 3:
        print(f'Usage: {sys.argv[0]} <file_name> <delphi_version>')
        exit(-1)

    main(sys.argv[1], int(sys.argv[2]))
