from binaryninja import BackgroundTaskThread, BinaryView, PluginCommand

from .bnhelpers import BNHelpers
from .delphi_analyser import ClassFinder, DelphiClass
from .ui.delphi_vmt_widget import DelphiVmtWidget


class AnalizeDelphiBinaryTask(BackgroundTaskThread):
    def __init__(self, bv):
        BackgroundTaskThread.__init__(self, "Searching VMTs...", can_cancel=True)
        self._bv = bv

    def run(self):
        global _vmt_dock_widget

        self._bv.begin_undo_actions()

        _vmt_dock_widget.clear_vmts()

        delphi_version = 7
        finder = ClassFinder(self._bv, delphi_version)
        addy = finder.get_possible_vmt()

        while addy:
            delphi_vmt = DelphiClass(self._bv, delphi_version, addy)

            if delphi_vmt.is_valid:
                BNHelpers.create_vmt_struct(self._bv, delphi_vmt)
                _vmt_dock_widget.add_vmt(delphi_vmt.start, delphi_vmt.class_name)

            addy = finder.get_possible_vmt()

        self._bv.commit_undo_actions()
        self._bv.update_analysis()


def analyze_delphi_binary(bv: BinaryView):
    t = AnalizeDelphiBinaryTask(bv)
    t.start()


# FIXME: Dirty but I don't know how to do better
_vmt_dock_widget: DelphiVmtWidget = None

if __name__ != '__main__':
    _vmt_dock_widget = DelphiVmtWidget.create_dock_widget()

    PluginCommand.register(
        'DelphiNinja\\Analyze current binary',
        'Search and define strutures for Delphi VMTs',
        analyze_delphi_binary
    )
