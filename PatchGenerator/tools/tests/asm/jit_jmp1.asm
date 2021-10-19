mov r3, 0x1
ldxw r1, [r1]
ldxdw r2, [r1]
ldxb r1, [r2]
lsh r1, 0x38
arsh r1, 0x38
jsgt r1, 0xffffffff, +6  # ---> 14
mov r3, 0x2
ldxb r4, [r2+1]
lsh r4, 0x38
arsh r4, 0x38
mov r5, 0x0
jsgt r5, r4, +23  #---> 47
and r1, 0x7f
jne r3, 0x1, +4 #---> 20
mov r0, 0xffffffea
jgt r1, 0xfffffff, +1 #---> return 0xffffffea
mov r0, 0x0
exit
ldxb r4, [r2+1]
and r4, 0x7f
lsh r4, 0x7
or r4, r1
mov r1, r4
jeq r3, 0x2, -10 #---> 16
ldxb r1, [r2+2]
and r1, 0x7f
lsh r1, 0xe
or r1, r4
jeq r3, 0x3, -15 #---> 16
ldxb r2, [r2+3]
and r2, 0x7f
lsh r2, 0x15
or r2, r1
mov r1, r2
ja -21 #---> 16
mov r3, 0x3
ldxb r4, [r2+2]
lsh r4, 0x38
arsh r4, 0x38
jsgt r4, 0xffffffff, -28  #---> 14
mov r3, 0x4
ldxb r4, [r2+3]
lsh r4, 0x38
arsh r4, 0x38
jsgt r4, 0xffffffff, -33  #---> 14
lddw r0, 0xffffffea
# lddw[2] r0, 0x0
ldxb r4, [r2+4]
lsh r4, 0x38
arsh r4, 0x38
mov r3, 0x1
jsgt r4, 0xffffffff, -35  #---> 19, return 0
ja -41                    #---> 14