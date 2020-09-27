#!/usr/bin/env python
import os, sys
from binaryninja import BinaryView, BinaryViewType, LogLevel
from typing import Dict
from graphviz import Digraph

sys.path.insert(0, os.path.pardir)
from delphi_analyser import ClassFinder, DelphiClass
from bnlogger import BNLogger


def create_graph(vmt_map: Dict[int, DelphiClass]):
    g = Digraph('VMT')

    for vmt in vmt_map.values():
        if vmt.parent_vmt == 0 and vmt.class_name == 'TObject':
            continue

        if vmt.parent_vmt == 0:
            raise RuntimeError('The top level parent must be TObject')

        if vmt.parent_vmt not in vmt_map:
            BNLogger.log(f'Unknown parent at address {hex(vmt.parent_vmt)} for {vmt.class_name}', LogLevel.WarningLog)
            continue

        g.edge(vmt_map[vmt.parent_vmt].class_name, vmt.class_name)

    g.view('VMT', cleanup=True)


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
    BNLogger.log('Searching for VMT...')

    finder = ClassFinder(bv, delphi_version)
    addy = finder.get_possible_vmt()
    vmt_map = {}

    while addy:
        delphi_class = DelphiClass(bv, delphi_version, addy)
        addy = finder.get_possible_vmt()

        if not delphi_class.is_valid:
            continue

        vmt_map[delphi_class.start] = delphi_class

    BNLogger.log('Creating Graph...')
    create_graph(vmt_map)


if __name__ == '__main__':
    if len(sys.argv) != 3:
        print(f'Usage: {sys.argv[0]} <file_name> <delphi_version>')
        exit(-1)

    main(sys.argv[1], int(sys.argv[2]))
