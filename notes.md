0x383e0 main ds pointer

FUN_2000_bef4 < menu


       3000:1dee b8 86 3e        MOV        AX,0x3e86
       3000:1df1 8c da           MOV        DX,DS
       3000:1df3 a3 e0 b6        MOV        [0xb6e0],AX
       3000:1df6 89 16 e2 b6     MOV        word ptr [0xb6e2],DX
       3000:1dfa b8 80 3c        MOV        AX,0x3c80
       3000:1dfd 8c da           MOV        DX,DS
       3000:1dff a3 e8 b6        MOV        [0xb6e8],AX
       3000:1e02 89 16 ea b6     MOV        word ptr [0xb6ea],DX
...

lets hook these that appear on the initial screen
2000:1388		p_string255 "Press any key to continue."
2000:3bf9		p_string255 "Press any key to continue."

also lets figure out how far on the entry point do we get
lets add report hooks per line on its initial seq

                                                            




                                                             AFK
