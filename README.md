# ida-psx-gte
IDA Pro plugin that implements disassembly of PlayStation COP2 MIPS instructions.\
Based on ida-emotionengine plugin by oct0xor: https://github.com/oct0xor/ida-emotionengine
### Warning
Since there isn't good way to detect PS1 code/database, plugin is active on every little endian mips database (mipsl processor type in ida). This can cause some incompatibilities with non PS1 databases when cpu have implemented COP2/CP2 opcodes that collide with PS1 opcodes, specially for lwc2/ctc2/mtc2/etc. For now there is nothing i can do about it, you need to manually remove plugin. Changes are not stored in databases so opening different db with that plugin active doesn't gonna break that database assembly.  
### Before
![before](https://github.com/Goatman13/ida-psx-gte/assets/101417270/ebee2079-680c-464e-959d-471257d9a818)
### After
![after](https://github.com/Goatman13/ida-psx-gte/assets/101417270/82df4685-b8a9-4de8-89bc-385dac1f0747)
