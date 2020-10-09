import copy
from binaryninja import BinaryView, interaction, Architecture

_version_mapping = [
    ('Delphi 2', 2),
    ('Delphi 3', 3),
    ('Delphi 4', 4),
    ('Delphi 5', 5),
    ('Delphi 6', 6),
    ('Delphi 7', 7),
    ('Delphi 2005', 2005),
    ('Delphi 2006', 2006),
    ('Delphi 2007', 2007),
    ('Delphi 2009', 2009),
    ('Delphi 2010', 2010),
    ('Delphi 2011', 2011),
    ('Delphi 2012', 2012),
    ('Delphi 2013', 2013),
    ('Delphi 2014', 2014)
]

_arch_mapping = [
    ('32 bits', 4),
    ('64 bits', 8),
]


def show_delphi_modal(bv: BinaryView):
    global _version_mapping
    global _arch_mapping

    arch_mapping = copy.copy(_arch_mapping)

    if bv.arch is not None and bv.arch.address_size == 8:
        arch_mapping.reverse()

    version_field = interaction.ChoiceField('Delphi version', [x for x, _ in _version_mapping])

    arch_field = interaction.ChoiceField(
        'Architecture (ptr size)',
        [x for x, _ in arch_mapping]
    )

    normalize_section_name = lambda x: f'{x.name} {{0x{x.start:x}-0x{x.end:x}}}'
    normalize_section_tuple = lambda x: (normalize_section_name(x), (x.start, x.end))

    sections = sorted(bv.sections.values(), key=lambda x: x.start)
    range_mapping = [('Whole binary', (bv.start, bv.end))] + [normalize_section_tuple(x) for x in sections]
    range_field = interaction.ChoiceField('Search area', [x for x, _ in range_mapping])

    result = interaction.get_form_input([version_field, arch_field, range_field], "Search options")

    if not result:
        return None

    return {
        'delphi_version': _version_mapping[version_field.result][1],
        'offset_ptr_size': arch_mapping[arch_field.result][1],
        'start': range_mapping[range_field.result][1][0],
        'end': range_mapping[range_field.result][1][1],
    }
