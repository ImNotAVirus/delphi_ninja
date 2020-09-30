from binaryninja import BinaryView, Symbol, SymbolType, types, Type

from delphi_analyser import DelphiClass
from constants import VMTFieldTypes


class BNHelpers(object):
    @staticmethod
    def create_vmt_struct(bv: BinaryView, vmt: DelphiClass) -> bool:
        if not vmt.is_valid:
            return False

        address_size = bv.address_size
        vmt_offsets = vmt.vmt_offsets
        offsets = vmt_offsets.__dict__.items()
        offset_map = {y:x for x, y in offsets}
        offset = min(offset_map.keys()) - address_size

        vmt_struct = types.Structure()
        field_types = VMTFieldTypes(bv.arch)

        while True:
            offset += address_size

            if offset <= vmt_offsets.cVmtParent:
                # Define non-method members
                name = offset_map[offset]
                field_type = getattr(field_types, name)
                vmt_struct.append(field_type, name)
                continue

            # Define Class virtual methods
            value = vmt.read32(offset)

            if value == 0:
                continue

            if value not in vmt.virtual_methods:
                break

            # Create function if not exists
            if bv.get_function_at(value) is None:
                bv.create_user_function(value)

            function_name = bv.get_function_at(value).name
            method_name = vmt.virtual_methods[value]

            if function_name.startswith('sub_'):
                bv.define_user_symbol(Symbol(
                    SymbolType.FunctionSymbol,
                    value,
                    method_name
                ))

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

            field_name = method_name.split('.')[-1]
            vmt_struct.append(field_type, field_name)

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
            return allow_null

        code_section = bv.sections['CODE']
        return addy >= code_section.start and addy < code_section.end
