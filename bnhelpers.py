from binaryninja import BinaryView, Symbol, SymbolType, types, Type

from .delphi import DelphiVMT
from .delphi.constants import VMTFieldTypes

try:
    StructureType = types.StructureBuilder
except AttributeError:
    StructureType = types.Structure

class BNHelpers(object):
    @staticmethod
    def create_vmt_struct(bv: BinaryView, vmt: DelphiVMT) -> bool:
        if not vmt.is_valid:
            return False

        try:
            vmt_struct = types.StructureBuilder.create()
        except AttributeError:
            vmt_struct = types.Structure()

        if not BNHelpers._add_vmt_fields(bv, vmt, vmt_struct):
            return False

        if not BNHelpers._add_vmt_methods(bv, vmt, vmt_struct):
            return False

        struct_type = Type.structure_type(vmt_struct)
        bv.define_user_data_var(vmt.start, struct_type)
        # bv.define_user_type(f'vmt{vmt.class_name}', struct_type)

        # Create Symbole for VMT
        vmt_sym = Symbol(SymbolType.DataSymbol, vmt.start, f'vmt{vmt.class_name}')
        bv.define_user_symbol(vmt_sym)
        return True


    # Protected methods

    @staticmethod
    def _add_vmt_fields(bv: BinaryView, vmt: DelphiVMT, out_struct: StructureType) -> bool:
        offset_ptr_size = vmt.offset_ptr_size
        field_types = VMTFieldTypes(bv.arch)
        vmt_offsets = vmt.vmt_offsets
        offsets = vmt_offsets.__dict__.items()
        offset_map = {y:x for x, y in offsets}

        for offset in range(vmt_offsets.cVmtSelfPtr, vmt_offsets.cVmtParent+1, offset_ptr_size):
            if offset == vmt_offsets.cVmtClassName:
                if not BNHelpers.__create_class_name_type(bv, vmt, out_struct):
                    return False
                continue

            name = offset_map[offset]
            field_type = getattr(field_types, name)
            out_struct.append(field_type, name)

        return True


    @staticmethod
    def _add_vmt_methods(bv: BinaryView, vmt: DelphiVMT, out_struct: StructureType) -> bool:
        offset_ptr_size = vmt.offset_ptr_size

        if not vmt.seek_to_vmt_offset(vmt.vmt_offsets.cVmtParent + offset_ptr_size):
            return False

        for _ in range(len(vmt.virtual_methods)):
            value = vmt.read_ptr()

            if value == 0:
                continue

            if value not in vmt.virtual_methods:
                prev_offset = vmt.br_offset - offset_ptr_size
                raise RuntimeError(
                    f'Invalid method address detected at 0x{prev_offset:08x} ({vmt.class_name})')

            # Create function if not exists
            if bv.get_function_at(value) is None:
                bv.create_user_function(value)

            function = bv.get_function_at(value)

            # Set method name if not already set
            function_name = function.name
            method_name = vmt.virtual_methods[value]

            if function_name.startswith('sub_'):
                bv.define_user_symbol(Symbol(
                    SymbolType.FunctionSymbol,
                    value,
                    method_name
                ))

            # Add field to structure
            field_type = Type.pointer(
                bv.arch,
                Type.function(
                    function.return_type,
                    [(Type.void() if x.type is None else x.type) for x in function.parameter_vars],
                    function.calling_convention
                )
            )

            field_name = method_name.split('.')[-1]
            out_struct.append(field_type, field_name)

        return True


    # Private methods

    @staticmethod
    def __create_class_name_type(bv: BinaryView, vmt: DelphiVMT, out_struct: StructureType) -> bool:
        vmt_offsets = vmt.vmt_offsets

        if not vmt.seek_to_vmt_offset(vmt_offsets.cVmtClassName):
            return False

        class_name_ptr = vmt.read_ptr()

        if class_name_ptr is None:
            return False

        if not vmt.seek_to_code(class_name_ptr):
            return False

        class_name_len = vmt.read8()

        if class_name_len is None:
            return False


        try:
            class_name_struct = types.StructureBuilder.create()
        except AttributeError:
            class_name_struct = types.Structure()

        class_name_struct.append(Type.int(1, False), 'length')
        class_name_struct.append(Type.array(Type.char(), class_name_len), 'value')
        struct_type = Type.structure_type(class_name_struct)

        bv.define_user_data_var(class_name_ptr, struct_type)
        out_struct.append(Type.pointer(bv.arch, struct_type), 'cVmtClassName')

        # Create Symbole for class name
        class_name_sym = Symbol(SymbolType.DataSymbol, class_name_ptr, f'{vmt.class_name}Name')
        bv.define_user_symbol(class_name_sym)

        return True
