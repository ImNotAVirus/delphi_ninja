import binaryninja
from binaryninja import BackgroundTaskThread, BinaryView, PluginCommand, Tag, interaction
from binaryninja.enums import MessageBoxButtonSet, MessageBoxIcon, MessageBoxButtonResult

from .bnhelpers import BNHelpers
from .delphi import DelphiAnalyzer, DelphiVMT
from .ui import modal


class AnalyzeDelphiVmtsTask(BackgroundTaskThread):
    def __init__(self, bv: BinaryView, tag_type: Tag, delphi_version: int, offset_ptr_size: int,
                start: int, end: int):
        BackgroundTaskThread.__init__(self, 'Searching for VMTs...', can_cancel=True)
        self._bv = bv
        self._tag_type = tag_type
        self._delphi_version = delphi_version
        self._offset_ptr_size = offset_ptr_size
        self._search_start = start
        self._search_end = end


    def run(self):
        self._bv.begin_undo_actions()

        analyzer = DelphiAnalyzer(self._bv, self._delphi_version, self._offset_ptr_size,
            self._search_start, self._search_end)
        analyzer.update_analysis_and_wait(self.analyze_callback)

        self._bv.commit_undo_actions()
        self._bv.update_analysis()


    def analyze_callback(self, delphi_vmt: DelphiVMT):
        self.progress = f'VMT found at 0x{delphi_vmt.start:08x} ({delphi_vmt.class_name})'

        BNHelpers.create_vmt_struct(self._bv, delphi_vmt)

        self._bv.create_user_data_tag(
            delphi_vmt.start,
            self._tag_type,
            delphi_vmt.class_name,
            unique=True)

        # Removal of false positives functions
        # /!\ Not really sure about that
        for function in self._bv.get_functions_containing(delphi_vmt.start):
            if function.name.startswith('sub_') or function.name == 'vmt' + delphi_vmt.class_name:
                self._bv.remove_user_function(function)

        # Same here
        for table_addr in delphi_vmt.table_list.keys():
            for function in self._bv.get_functions_containing(table_addr):
                if function.name.startswith('sub_'):
                    self._bv.remove_user_function(function)


def clear_tags(bv: BinaryView, tag_type_name: str):
    tags = [(x, y) for x, y in bv.data_tags if y.type.name == tag_type_name]

    if not tags:
        return

    result = interaction.show_message_box(
        'Delete old tag?',
        ('DelphiNinja has detected several tags associated with VMTs. Would you like to '
        'remove these tags?\nWARNING: This will not remove associated structures.'),
        MessageBoxButtonSet.YesNoButtonSet,
        MessageBoxIcon.QuestionIcon
    )

    if result != MessageBoxButtonResult.YesButton:
        return

    for addy, tag in tags:
        bv.remove_user_data_tag(addy, tag)


def analyze_delphi_vmts(bv: BinaryView):
    type_name = 'Delphi VMTs'
    tt = bv.tag_types[type_name] if type_name in bv.tag_types else bv.create_tag_type(type_name, '🔍')

    result = modal.show_delphi_modal(bv)

    if result is None:
        return

    clear_tags(bv, type_name)

    t = AnalyzeDelphiVmtsTask(
        bv,
        tt,
        result['delphi_version'],
        result['offset_ptr_size'],
        result['start'],
        result['end'])

    t.start()


if binaryninja.core_ui_enabled():
    PluginCommand.register(
        'DelphiNinja\\Analyze current binary',
        'Search and define strutures for Delphi VMTs',
        analyze_delphi_vmts
    )
