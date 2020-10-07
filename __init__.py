import binaryninja
from binaryninja import BackgroundTaskThread, BinaryView, PluginCommand, Tag, interaction
from binaryninja.enums import MessageBoxButtonSet, MessageBoxIcon, MessageBoxButtonResult

from .bnhelpers import BNHelpers
from .delphi import DelphiAnalyzer, DelphiVMT


class AnalyzeDelphiVmtsTask(BackgroundTaskThread):
    def __init__(self, bv: BinaryView, tag_type: Tag, delphi_version: int):
        BackgroundTaskThread.__init__(self, 'Searching for VMTs...', can_cancel=True)
        self._bv = bv
        self._tag_type = tag_type
        self._delphi_version = delphi_version


    def run(self):
        self._bv.begin_undo_actions()

        analyzer = DelphiAnalyzer(self._bv, self._delphi_version)
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

    choices = [
        'Delphi 2',
        'Delphi 3',
        'Delphi 4',
        'Delphi 5',
        'Delphi 6',
        'Delphi 7',
        'Delphi 2005',
        'Delphi 2006',
        'Delphi 2007',
        'Delphi 2009',
        'Delphi 2010',
        'Delphi 2011',
        'Delphi 2012',
        'Delphi 2013',
        'Delphi 2014'
    ]

    index = interaction.get_choice_input(
        'Please, select the Delphi version',
        'Delphi version',
        choices
    )

    clear_tags(bv, type_name)

    t = AnalyzeDelphiVmtsTask(bv, tt, int(choices[index][7:]))
    t.start()


if binaryninja.core_ui_enabled():
    PluginCommand.register(
        'DelphiNinja\\Analyze current binary',
        'Search and define strutures for Delphi VMTs',
        analyze_delphi_vmts
    )
