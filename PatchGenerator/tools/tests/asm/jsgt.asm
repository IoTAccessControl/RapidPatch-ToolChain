mov r1, 0xffffffff
mov r0, 0
jsgt r1, 0xffffffff, +1
mov r0, 2
exit