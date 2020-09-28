from binaryninja import BinaryView, Symbol, SymbolType, types, Type
import struct

from delphi_analyser import DelphiClass
from constants import VMTFieldTypes


class BNHelpers(object):
    @staticmethod
    def create_vmt_struct(bv: BinaryView, vmt: DelphiClass) -> bool:
        if not vmt.is_valid:
            return False

        vmt_offsets = vmt.vmt_offsets
        offsets = vmt_offsets.__dict__.items()
        offset_map = {y:x for x, y in offsets}
        begin = min(offset_map.keys())

        vmt_struct = types.Structure()
        field_types = VMTFieldTypes(bv.arch)

        for offset in range(begin, 0, 4):
            if  offset not in offset_map:
                    raise RuntimeError(f'Invalid offset: {hex(offset)}')

            name = offset_map[offset]

            if offset <= vmt_offsets.cVmtParent:
                field_type = getattr(field_types, name)
                vmt_struct.append(field_type, name)
                continue

            # Define Class methods
            value = vmt.read32(offset)

            if value == 0:
                continue

            if not BNHelpers._isValidCodeAdr(bv, value):
                raise RuntimeError(f'Invalid function address at: {value} ({vmt.class_name})')

            if bv.get_function_at(value) is None:
                bv.create_user_function(value)
                vmt_sym = Symbol(SymbolType.FunctionSymbol, value, f'{vmt.class_name}.{name[4:]}')
                bv.define_user_symbol(vmt_sym)

            # Add field to structure
            method = bv.get_function_at(value)
            field_type = Type.pointer(
                bv.arch,
                Type.function(
                    method.return_type,
                    [x.type for x in method.parameter_vars],
                    method.calling_convention
                )
            )

            vmt_struct.append(field_type, name)

        # Create VMT Structure
        struct_type = Type.structure_type(vmt_struct)
        # bv.define_user_type(f'vmt{vmt.class_name}', struct_type)
        bv.define_user_data_var(vmt.start, struct_type)

        # Create Symbole for VMT
        vmt_sym = Symbol(SymbolType.DataSymbol, vmt.start, f'vmt{vmt.class_name}')
        bv.define_user_symbol(vmt_sym)
        return True


    @staticmethod
    def _isValidCodeAdr(bv: BinaryView, addy: int, allow_null=False) -> bool:
        if addy == 0:
            return True

        code_section = bv.sections['CODE']
        return addy >= code_section.start and addy < code_section.end
