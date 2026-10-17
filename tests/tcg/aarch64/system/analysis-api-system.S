/* Local AI-assisted plugin API experiment; not for upstream submission. */
/* SPDX-License-Identifier: GPL-2.0-or-later */
.global _start
_start:
    adr x1, count
    mov x2, #16
1:
    ldr x3, [x1]
    add x3, x3, #1
    str x3, [x1]
    subs x2, x2, #1
    b.ne 1b
    mov x0, #0x20
    adr x1, exit_args
    hlt #0xf000
2:
    b 2b
.balign 8
count:
    .quad 0
exit_args:
    .quad 0x20026
    .quad 0
