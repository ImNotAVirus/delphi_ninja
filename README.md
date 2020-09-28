# DelphiNinja

**TODO**: Description

## Features

- [x] Ability to scan a binary and find potential VMT addresses
- [x] Get ClassName from a VMT address
- [x] Get ParentVmt from a VMT address
- [x] Get InstanceSize from a VMT address
- [ ] Get ClassMethods from a VMT address
- [ ] Get ClassMembers for a DelphiClass (inspect methods?)
- [x] Create Binary Ninja structure for each VMT
- [ ] Create Binary Ninja structure for a DelphiClass
- [ ] For ClassMethods, set `this` type (`ECX` I think) to structure
- [ ] Export all Delphi structures to C/C++ code
- [ ] Auto detect Delphi version
- [ ] Load IDR's Knowledge bases for system types

## TODO

- [ ] Support 64 bits binaries (`read32` -> `read64`, offsets, ...)
