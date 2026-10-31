/*
 * For the relocatable link of smb2man.irx: fold the per-function and
 * per-object sections of -ffunction-sections/-fdata-sections back into
 * the plain sections iopfixup expects.
 */
SECTIONS
{
  .text   : { *(.text .text.*) }
  .rodata : { *(.rodata .rodata.*) }
  .data   : { *(.data .data.*) }
  .sdata  : { *(.sdata .sdata.*) }
  .sbss   : { *(.sbss .sbss.*) *(.scommon) }
  .bss    : { *(.bss .bss.*) *(COMMON) }
}
