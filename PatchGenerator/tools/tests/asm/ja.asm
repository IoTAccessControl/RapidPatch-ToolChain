mov r0, 1
ja +2      # --> 5
mov r0, 2
exit
mov r0, 3 
ja -3     #---> return 3 
mov r0, 4
jsgt r0, 3, -5 # ---> return 4
mov r0, 5