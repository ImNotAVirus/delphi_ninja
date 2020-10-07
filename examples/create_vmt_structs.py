#!/usr/bin/env python
from binaryninja import BinaryView, BinaryViewType

import importlib
import sys
from os import path

# from delphi_ninja.delphi import DelphiAnalyzer, DelphiVMT
# from delphi_ninja.bnlogger import BNLogger
# from delphi_ninja.bnhelpers import BNHelpers

module_dir = path.dirname(path.dirname(path.abspath(__file__)))
module_name = path.basename(module_dir)
module_parent = path.dirname(module_dir)
sys.path.insert(0, module_parent)
delphi_ninja = importlib.import_module(module_name)
DelphiAnalyzer = delphi_ninja.delphi.DelphiAnalyzer
DelphiVMT = delphi_ninja.delphi.DelphiVMT
BNLogger = delphi_ninja.bnlogger.BNLogger
BNHelpers = delphi_ninja.bnhelpers.BNHelpers


def analyze_callback(vmt: DelphiVMT, bv: BinaryView):
    BNLogger.log(f'Creating type for: {vmt}')
    BNHelpers.create_vmt_struct(bv, vmt)


def main(target: str, delphi_version: int):
    # Just disable some features for large binaries
    opts = {
        'analysis.mode': 'full',
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

    analyzer = DelphiAnalyzer(bv, delphi_version)
    analyzer.update_analysis_and_wait(lambda vmt: analyze_callback(vmt, bv))

    bv.update_analysis_and_wait()

    BNLogger.log(f'Saving database: `{target}.bndb`...')
    bv.create_database(f'{target}.bndb')


if __name__ == '__main__':
    if len(sys.argv) != 3:
        print(f'Usage: {sys.argv[0]} <file_name> <delphi_version>')
        exit(-1)

    main(sys.argv[1], int(sys.argv[2]))
