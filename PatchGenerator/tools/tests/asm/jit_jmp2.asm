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
jsgt r5, r4, +6  #---> 20
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
mov r0, 5