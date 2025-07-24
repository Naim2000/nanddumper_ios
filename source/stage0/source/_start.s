.thumb

.section .init
.globl _start
_start:
start:
    ldr r1, =0x10100000 @ temporary stack
    mov sp, r1
    ldr r0, =0xDEADBEEF @ argument
    ldr r1, =0x0BADC0DE @ our entrypoint
    blx r1

.align 2
    bx pc
    nop

.arm
chill:
    /*
     * "i sleep"
     * - starlet
     *
     * https://developer.arm.com/documentation/ddi0198/e/programmer-s-model/register-descriptions/cache-operations-register-c7?lang=en
     */
    mov r0, #0x0
    mcr p15, 0, r0, c7, c0, 4
    b chill
