ldxw r2, [r1+4]
stxdw [r10-40], r2
ldxw r8, [r1]
stxdw [r10-32], r8
add r8, 0xffffffff
ldxb r1, [r8+1]
add r8, 0x1
jne r1, 0x0, -3
lddw r0, 0xffffffff
# lddw[2] r0, 0x0
ldxdw r1, [r10-32]
jeq r1, 0x0, +88
ldxdw r1, [r10-32]
sub r8, r1
mov r0, r8
and r0, 0xffff
mov r1, 0x2
jgt r1, r0, +82
mov r1, 0x0
mov r9, 0x1
mov r2, 0xffff
stxdw [r10-8], r2
ldxdw r2, [r10-32]
add r2, 0x1
stxdw [r10-16], r2
mov r7, 0x0
mov r2, 0x0
stxdw [r10-24], r2
ja +22
mov r3, 0x0
stxdw [r10-24], r3
mov r3, r6
and r3, 0xffff
jeq r3, 0x0, +54
lsh r1, 0x20
rsh r1, 0x20
ldxdw r5, [r10-32]
mov r3, r5
add r3, r2
mov r2, r5
add r2, r1
sub r0, r4
add r0, 0x1
mov r1, 0x0
stxdw [r10-24], r1
ldxdw r1, [r10-40]
mov r4, r0
mov r5, 0x0
call 0x2
sub r8, r6
ja +37
ldxdw r6, [r10-24]
mov r2, r7
and r2, 0xffff
ldxdw r3, [r10-32]
add r3, r2
ldxb r2, [r3]
jne r2, 0x20, +30
mov r3, r8
and r3, 0xffff
add r1, 0x1
mov r4, r1
and r4, 0xffff
stxdw [r10-24], r6
jge r4, r3, +23
mov r2, r9
and r2, 0xffff
ldxdw r5, [r10-32]
add r5, r2
ldxb r5, [r5]
jne r5, 0x20, -42
mov r5, r8
add r5, r6
ldxdw r4, [r10-8]
add r5, r4
stxdw [r10-24], r5
add r3, 0xffffffff
mov r4, r2
jeq r3, r2, +9
add r6, 0x1
ldxdw r5, [r10-16]
add r5, r2
add r2, 0x1
add r4, 0x1
ldxb r5, [r5]
jne r5, 0x20, -57
jeq r3, r2, +1
ja -9
ldxdw r1, [r10-8]
add r1, 0xffffffff
stxdw [r10-8], r1
add r9, 0x1
add r7, 0x1
mov r1, r7
and r1, 0xffff
mov r0, r8
and r0, 0xffff
mov r2, r0
add r2, 0xffffffff
jsgt r2, r1, -49
exit