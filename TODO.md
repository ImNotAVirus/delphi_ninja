# DelphiNinja

## Features

- [x] Ability to scan a binary and find potential VMT addresses
- [x] Get ClassName from a VMT address
- [x] Get ParentVmt from a VMT address
- [x] Get InstanceSize from a VMT address
- [x] Get ClassMethods from a VMT address
- [ ] Get ClassMembers for a DelphiVMT (inspect methods?)
- [x] Create Binary Ninja structure for each VMT
- [ ] Define a Binary Ninja structure for a Delphi Class
- [ ] For ClassMethods, set `this` type (register) to the previously created structure
- [ ] Export all Delphi Class structures to C/C++ code
- [ ] Auto detect Delphi version
- [ ] Load IDR's Knowledge bases for system types

## TODO

- [ ] Support 64 bits binaries (`read32` -> `read64`, offsets, ...)
- [ ] Support all architecture (even `raw` ~> remove hardcoded `bv.sections['CODE']`)
