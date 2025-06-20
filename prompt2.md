tracking the menu

Hotkey: P
Item Color: Yellow
Line Text: PLAY GAME

Hotkey: R
Item Color: Green
Line Text: RESTORE SAVED GAME

Hotkey: S
Item Color: Green
Line Text: SAVE GAME

Hotkey: R
Item Color: Green
Line Text: RESTART LEVEL

Hotkey: B
Item Color: Red
Line Text: BOSS SCREEN

Hotkey: R
Item Color: Cyan
Line Text: REGISTRATION INFORMATION

Hotkey: R
Item Color: Cyan
Line Text: RULES

Hotkey: G
Item Color: Cyan
Line Text: GAME CONTROLS

Hotkey: H
Item Color: Cyan
Line Text: HOW TO FINISH LEVEL #1

Hotkey: H
Item Color: Cyan
Line Text: HINT FOR CURRENT LEVEL

Hotkey: M
Item Color: Yellow
Line Text: MAKE CRABS MOVE SLOWER

Hotkey: T
Item Color: Magenta
Line Text: TURN SOUND OFF (NOW ON)

Hotkey: S
Item Color: Magenta
Line Text: SWITCH TO JOYSTICK

Hotkey: E
Item Color: Green
Line Text: EXIT GAME

      identify the logic function creating this menu

       2000:cf17 19              db         19h
       2000:cf18 2a 2a 2a        ds         "***** F.GODMOM MENU *****"
                 2a 2a 20 
                 46 2e 47 
       2000:cf31 10              db         10h
       2000:cf32 20 20 20        ds         "       PLAY GAME"
                 20 20 20 
                 20 50 4c 
       2000:cf42 19              db         19h
       2000:cf43 20 20 20        ds         "       RESTORE SAVED GAME"
                 20 20 20 
                 20 52 45 
       2000:cf5c 10              ??         10h
       2000:cf5d 20 20 20        ds         "       SAVE GAME"
                 20 20 20 
                 20 53 41 
       2000:cf6d 14              ??         14h
       2000:cf6e 20 20 20        ds         "       RESTART LEVEL"
                 20 20 20 
                 20 52 45 
       2000:cf82 12              ??         12h
       2000:cf83 20 20 20        ds         "       BOSS SCREEN"
                 20 20 20 
                 20 42 4f 
       2000:cf95 1f              ??         1Fh
       2000:cf96 20 20 20        ds         "       REGISTRATION INFORMATION"
                 20 20 20 
                 20 52 45 
       2000:cfb5 0c              ??         0Ch
       2000:cfb6 20 20 20        ds         "       RULES"
                 20 20 20 
                 20 52 55 
       2000:cfc2 14              ??         14h
       2000:cfc3 20 20 20        ds         "       GAME CONTROLS"
                 20 20 20 
                 20 47 41 
       2000:cfd7 1d              ??         1Dh
       2000:cfd8 20 20 20        ds         "       HOW TO FINISH LEVEL #1"
                 20 20 20 
                 20 48 4f 
       2000:cff5 1d              ??         1Dh
       2000:cff6 20 20 20        ds         "       HINT FOR CURRENT LEVEL"
                 20 20 20 
                 20 48 49 
       2000:d013 05              ??         05h
       2000:d014 48 45 4c        ds         "HELP{"
                 50 7b
       2000:d019 05              ??         05h
       2000:d01a 54 45 58        ds         "TEXT{"
                 54 7b
       2000:d01f 17              ??         17h
       2000:d020 20 20 20        ds         "       MAKE CRABS MOVE "
                 20 20 20 
                 20 4d 41 
       2000:d037 06              ??         06h
       2000:d038 46 41 53        ds         "FASTER"
                 54 45 52
       2000:d03e 06              ??         06h
       2000:d03f 53 4c 4f        ds         "SLOWER"
                 57 45 52
       2000:d045 12              ??         12h
       2000:d046 20 20 20        ds         "       TURN SOUND "
                 20 20 20 
                 20 54 55 
       2000:d058 0c              ??         0Ch
       2000:d059 4f 46 46        ds         "OFF (NOW ON)"
                 20 28 4e 
                 4f 57 20 
       2000:d065 0c              ??         0Ch
       2000:d066 4f 4e 20        ds         "ON (NOW OFF)"
                 28 4e 4f 
                 57 20 4f 
       2000:d072 11              ??         11h
       2000:d073 20 20 20        ds         "       SWITCH TO "
                 20 20 20 
                 20 53 57 
       2000:d084 08              ??         08h
       2000:d085 4b 45 59        ds         "KEYBOARD"
                 42 4f 41 
                 52 44
       2000:d08d 08              ??         08h
       2000:d08e 4a 4f 59        ds         "JOYSTICK"
                 53 54 49 
                 43 4b
       2000:d096 10              ??         10h
       2000:d097 20 20 20        ds         "       EXIT GAME"
                 20 20 20 
                 20 45 58 

