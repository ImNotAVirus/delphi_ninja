from enum import IntEnum


class VMTOffsets(object):
    def __init__(self, delphi_version: int):
        if delphi_version == 2:
            self.cVmtSelfPtr = -0x34
            self.cVmtInitTable = -0x30
            self.cVmtTypeInfo = -0x2C
            self.cVmtFieldTable = -0x28
            self.cVmtMethodTable = -0x24
            self.cVmtDynamicTable = -0x20
            self.cVmtClassName = -0x1C
            self.cVmtInstanceSize = -0x18
            self.cVmtParent = -0x14
            self.cVmtDefaultHandler = -0x10
            self.cVmtNewInstance = -0xC
            self.cVmtFreeInstance = -8
            self.cVmtDestroy = -4
        elif delphi_version == 3:
            self.cVmtSelfPtr = -0x40
            self.cVmtIntfTable = -0x3C
            self.cVmtAutoTable = -0x38
            self.cVmtInitTable = -0x34
            self.cVmtTypeInfo = -0x30
            self.cVmtFieldTable = -0x2C
            self.cVmtMethodTable = -0x28
            self.cVmtDynamicTable = -0x24
            self.cVmtClassName = -0x20
            self.cVmtInstanceSize = -0x1C
            self.cVmtParent = -0x18
            self.cVmtSafeCallException = -0x14
            self.cVmtDefaultHandler = -0x10
            self.cVmtNewInstance = -0xC
            self.cVmtFreeInstance = -8
            self.cVmtDestroy = -4
        elif delphi_version in [4, 5, 6, 7, 2005, 2006, 2007]:
            self.cVmtSelfPtr = -0x4C
            self.cVmtIntfTable = -0x48
            self.cVmtAutoTable = -0x44
            self.cVmtInitTable = -0x40
            self.cVmtTypeInfo = -0x3C
            self.cVmtFieldTable = -0x38
            self.cVmtMethodTable = -0x34
            self.cVmtDynamicTable = -0x30
            self.cVmtClassName = -0x2C
            self.cVmtInstanceSize = -0x28
            self.cVmtParent = -0x24
            self.cVmtSafeCallException = -0x20
            self.cVmtAfterConstruction = -0x1C
            self.cVmtBeforeDestruction = -0x18
            self.cVmtDispatch = -0x14
            self.cVmtDefaultHandler = -0x10
            self.cVmtNewInstance = -0xC
            self.cVmtFreeInstance = -8
            self.cVmtDestroy = -4
        elif delphi_version in [2009, 2010]:
            self.cVmtSelfPtr = -0x58
            self.cVmtIntfTable = -0x54
            self.cVmtAutoTable = -0x50
            self.cVmtInitTable = -0x4C
            self.cVmtTypeInfo = -0x48
            self.cVmtFieldTable = -0x44
            self.cVmtMethodTable = -0x40
            self.cVmtDynamicTable = -0x3C
            self.cVmtClassName = -0x38
            self.cVmtInstanceSize = -0x34
            self.cVmtParent = -0x30
            self.cVmtEquals = -0x2C
            self.cVmtGetHashCode = -0x28
            self.cVmtToString = -0x24
            self.cVmtSafeCallException = -0x20
            self.cVmtAfterConstruction = -0x1C
            self.cVmtBeforeDestruction = -0x18
            self.cVmtDispatch = -0x14
            self.cVmtDefaultHandler = -0x10
            self.cVmtNewInstance = -0xC
            self.cVmtFreeInstance = -8
            self.cVmtDestroy = -4
        elif delphi_version in [2011, 2012, 2013, 2014]:
            self.cVmtSelfPtr = -0x58
            self.cVmtIntfTable = -0x54
            self.cVmtAutoTable = -0x50
            self.cVmtInitTable = -0x4C
            self.cVmtTypeInfo = -0x48
            self.cVmtFieldTable = -0x44
            self.cVmtMethodTable = -0x40
            self.cVmtDynamicTable = -0x3C
            self.cVmtClassName = -0x38
            self.cVmtInstanceSize = -0x34
            self.cVmtParent = -0x30
            self.cVmtEquals = -0x2C
            self.cVmtGetHashCode = -0x28
            self.cVmtToString = -0x24
            self.cVmtSafeCallException = -0x20
            self.cVmtAfterConstruction = -0x1C
            self.cVmtBeforeDestruction = -0x18
            self.cVmtDispatch = -0x14
            self.cVmtDefaultHandler = -0x10
            self.cVmtNewInstance = -0xC
            self.cVmtFreeInstance = -8
            self.cVmtDestroy = -4
            # self.cVmtQueryInterface = 0
            # self.cVmtAddRef = 4
            # self.cVmtRelease = 8
            # self.cVmtCreateObject = 0xC
        else:
            raise RuntimeError(f'Unsuported Delphi version {delphi_version}')
