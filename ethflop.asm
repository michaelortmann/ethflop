;
; ethflop - a floppy drive emulator over Ethernet
; Copyright (C) 2019 Mateusz Viste
; Copyright (c) 2020 Michael Ortmann
;
; ethflop is a small TSR that hooks itself on INT 13h and emulates a floppy
; drive. All requests for this drive are forwarded through Ethernet towards
; an ethflopd server.
;
; BUILD:
;  nasm -f bin -o ethflop.com ethflop.asm
;
; This software is published under the terms of the ISC license.
;

STACKSIZE equ 690       ; private stack size for TSR (pkt drivers need much)
PROTOVER equ 0x01       ; protocol id
DBG equ 0               ; set to non-zero for enabling debug mode for:
                        ; 1=interrupt  ;  2=int+pktdrv
CPU 8086
org 100h

section .text  ; all goes into code segment

TSRBEGIN:  ; this label is used to compute the TSR size

jmp PROGSTART
STR_SIG db "EFLOP"    ; signature for locating the TSR in memory (5 bytes, so
                      ; the memory block below ends up WORD-aligned)

; ============================================================================
; === CONFIGURATION AND PKT BUFFER MEMORY BLOCK ==============================
; ============================================================================

; I am misusing the PSP location here by storing memory variables and packet
; header values inside PSP's command tail area. The command tail area is 127
; bytes big, which is a waste of space for a TSR, esp. since even the command
; line program won't ever take arguments longer than 25 bytes or so.
VARBLOCK equ 0xA2   ; starting at A2h means my cmd line tail can be up to 33
                    ; bytes long and the vars can hold up to 94 bytes of data
LASTOPSTATUS equ VARBLOCK     ; last op res as returned by int 13h,ah=1 (1 b)
DRIVEID equ VARBLOCK+1        ; emulated drive: 0=A, 1=B (1 byte)
PRVHANDLERBIOS equ VARBLOCK+2 ; prv int 13h handler address (4 bytes, far ptr)
PRVHANDLERDOS equ VARBLOCK+6  ; prv int 13h routine, as known by int 2F,ah=13h
PKTDRVR equ VARBLOCK+10       ; pkt drvr procedure address (4 bytes, far ptr)
PKTDRVRHANDLE equ VARBLOCK+14 ; packet driver handle (2 bytes)
PKTBUFBUSY equ VARBLOCK+16    ; "packet is in buffer" flag (0=empty) (1 byte)
BYTEVAR equ VARBLOCK+17       ; a BYTE variable for general purpose (1 byte)
ORIGSS equ VARBLOCK+18        ; used to save SS on TSR entry, restored on exit
ORIGSP equ VARBLOCK+20        ; used to save SP on TSR entry, restored on exit
                              ; two bytes available for future use here
HDR_BEGIN equ VARBLOCK+24
HDR_DMAC equ HDR_BEGIN        ; destination (server) MAC (6 bytes)
HDR_SMAC equ HDR_BEGIN+6      ; source (local) MAC (6 bytes)
HDR_ETYPE equ HDR_BEGIN+12    ; ethertype: data=0xEFDD, ctrl=0xEFDC (2 bytes)
HDR_PROTOVER equ HDR_BEGIN+14 ; protocol version (1 byte)
HDR_REQID equ HDR_BEGIN+15    ; request's seq number (1 byte)
HDR_FLOPID equ HDR_BEGIN+16   ; current virtual floppy id (8 bytes)
HDR_AX equ HDR_BEGIN+24       ; AX (2 bytes)
HDR_BX equ HDR_BEGIN+26       ; BX (2 bytes)
HDR_CX equ HDR_BEGIN+28       ; CX (2 bytes)
HDR_DX equ HDR_BEGIN+30       ; DX (2 bytes)
HDR_SECTNUM equ HDR_BEGIN+32  ; sect num for multisector READs and WRITEs (1b)
HDR_FFU equ HDR_BEGIN+33      ; for future use (word-padding) (1 byte)
HDR_END equ HDR_BEGIN+34
                              ; two bytes available for future use here
GETCURTICK equ VARBLOCK+60    ; this is a location in the PSP where I put the
                              ; timer routine at startup (max 14 bytes)

COMPUTEPKTCSUM equ VARBLOCK+74 ; this is a location in the PSP where I put the
                               ; cksum routine at startup (max 20 bytes)

; packet buffer, used for _BOTH_ SENDING *and* RECEIVING data
PKT_DMAC db "MOJMIR" ; SAME AS HDR_xxx
PKT_SMAC db "MILENA" ; SAME AS HDR_xxx
PKT_ETYPE dw 0       ; SAME AS HDR_xxx
PKT_PROTOVER db 0    ; SAME AS HDR_xxx
PKT_REQID db 0       ; SAME AS HDR_xxx
PKT_FLOPID dw 0,0,0,0; SAME AS HDR_xxx
PKT_AX dw 0          ; AX
PKT_BX dw 0          ; BX
PKT_CX dw 0          ; CX
PKT_DX dw 0          ; DX
PKT_SECTNUM db 0     ; sector number (used for multi-sector READs and WRITEs)
PKT_FFU db 'X'       ; for future use (word-padding)
PKT_DATA times 512 db 0 ; SECTOR DATA (for WRITE and READ ops)
PKT_CSUM dw 0        ; CHECKSUM (16 bit)
PKT_END:
; === END OF CONFIGURATION AND PKT BUFFER BLOCK ==============================


; ============================================================================
; === PACKET DRIVER RECEIVING ROUTINE ========================================
; ============================================================================
; this function is called two times by the packet driver. One time for saying
; that a packet is coming and how big it is, so the application can prepare a
; buffer for it and hand back a recv ptr to the packet driver:
;   ax = 0
;   cx = incoming pkt len (bytes)
;   ...expects to receive a buffer in ES:DI on return (0000:0000 on error)
; Second call tells that the frame has been copied into the recv buffer:
;   ax = 1
;   DS:SI = buffer location where packet awaits
; WARNING: this function must modify ONLY registers ES and DI! Packet drivers
; can get easily confused when any other register (or flag) is modified.
PKTDRVR_RECV:
or ax, ax   ; is ax=0? yes: packet on its way, not: packet received
jz short .PKTDRVR_RECV_PREP
mov [cs:PKTBUFBUSY], byte 1   ; mark buffer as 'full' and return
%if DBG = 2
mov [cs:DBGCOLOR], byte 0x50    ; violet
mov [cs:DBGVALUE], byte '.'
call VGADBG
%endif
retf
; packet driver wants to deliver a frame
.PKTDRVR_RECV_PREP:
; do I have available storage?
cmp [cs:PKTBUFBUSY], ah   ; test for zero (ah is guaranteed to be zero here)
jne short .PKTDRVR_RECV_REJECT_BUSY
; is frame len okay?
cmp cx, (PKT_END - PKT_DMAC) ; cx (frame len) must be exactly what I expect
jne short .PKTDRVR_RECV_REJECT_SIZE
; all good - return pkt buffer (cs:PKT_DMAC) in es:di
push cs
pop es
mov di, PKT_DMAC
retf
; reject frame (set es:di to 0000:0000)
.PKTDRVR_RECV_REJECT_SIZE:
%if DBG = 2
mov [cs:DBGCOLOR], byte 0x50    ; violet
mov [cs:DBGVALUE], byte '!'
call VGADBG
%endif
.PKTDRVR_RECV_REJECT_BUSY:
%if DBG = 2
mov [cs:DBGCOLOR], byte 0x50    ; violet
mov [cs:DBGVALUE], byte '%'
call VGADBG
%endif
xor di, di ; a byte shorter than mov di, 0
mov es, di
retf

; ============================================================================
; === PACKET DRIVER SENDING ROUTINE ==========================================
; ============================================================================
; sends the frame starting at PKT_DMAC. Applies HDR_ values first and computes
; checksum. Also waits until a valid answer is present in the PKT buffer.
; returns with a clear CF on success, set CF otherwise.
; this function ALWAYS sets ah=0x80 on exit
PKTDRVR_SEND:
; save registers
push ax
push bx
push cx
push dx
push si
push di
push ds
push es
; set ds to self (ds = cs)
push cs
pop ds
; mark the buffer as 'busy', so the packet driver won't be
; tempted to put some garbage there while I craft my frame.
mov [PKTBUFBUSY], byte 1
; increment reqid
inc byte [HDR_REQID]
; I will use BYTEVAR as a "dirty flag" variable: as long as it is zero, my
; data in pkt_buf did not change, so I can reuse it for retries.
mov [BYTEVAR], byte 0
; copy headers to packet
mov cx, (HDR_END-HDR_BEGIN)/2   ; /2 because I will copy WORDS, NOT BYTES
push ds
pop es
mov di, PKT_DMAC
mov si, HDR_DMAC
cld
rep movsw      ; [ES:DI++] = [DS:SI++], CX times
; compute checksum
call COMPUTEPKTCSUM
mov [PKT_CSUM], bx ; write csum to frame buffer
; AX is used for timeout detection (AL="current tick", AH="next tick")
call GETCURTICK     ; system timer is in BL now
mov al, bl          ; save it to AL...
mov ah, bl          ; ...and to AH...
inc ah              ; ...but AH should hold 'next state'
; send the frame out
.SENDPKTOUT:
push ax
mov ah, 4                   ; SendPkt()
mov cx, (PKT_END-PKT_DMAC)  ; how many bytes
mov si, PKT_DMAC
; simulated int
pushf
cli
call far [PKTDRVR]
       ; I can potentially loose packets here. If the remote srv answers super
       ; quick, the pktdrvr routine will see that PKTBUFF is still busy, thus
       ; rejecting the packet. I observed this on a virtual environment where
       ; ethflop (under DOSEMU) is on the same machine as ethflopd and both
       ; communicate through a loopback. As a work-around for this problem,
       ; the ethflopd server delays its answer by 0.5ms, so ethflop has enough
       ; time to prepare.
       ; One may think that a good idea would be to reset PKTBUFBUSY earlier,
       ; that is - before calling pkt_send()... but this would be worse: it
       ; could lead to races! If the pkt driver wanted to feed some weird pkt
       ; just before the send routine is called, ethflop would end up sending
       ; out a copy of the just-received frame instead of its own query.
mov [PKTBUFBUSY], byte 0 ; flag the pkt buffer as 'available'
pop ax
jc .SENDRETERR ; quit on PKTDRVR fail (neither MOV nor POP modify flags)
%if DBG = 2
mov [DBGCOLOR], byte 2   ; DBG, GREEN (pkt sent)
mov [DBGVALUE], byte 's'
call VGADBG
%endif
; wait for an answer
.WAITSOMEMORE:
; set dx to 0001h so I can use it for cmp/mov [var],0/1 (thx John Kerr-Mudd)
mov dx, 0x0100  ; DH=1  DL=0
; look for timeout (timer different than AL and AH)
call GETCURTICK     ; system timer is in BL now
; has it changed? (AL=original tick)
cmp bl, al
je .SKIPTIMERCHECK
; if it changed indeed, has it changed much? (AH=original tick+1)
cmp bl, ah         ; if timer changed, has it advanced more than +1 tick (AH)?
jne .SENDRETERR    ; if so, then between 55 and 110ms passed already: timeout!
; a tick passed without reply - re-send query again if pkt buf not dirty
cmp [BYTEVAR], dl       ; dl=0 (smaller than cmp [], 0)
jne .SKIPTIMERCHECK     ; dirty buffer, don't resend pkt
inc byte [PKTBUFBUSY]   ; mark pktbuf as busy, so pktdrv does not fill it
inc byte [BYTEVAR]      ; set the dirty var so I resend only once
; make sure PKTBUFBUSY is exactly 1 - otherwise it was full already
cmp [PKTBUFBUSY], dh    ; dh=1 (smaller than cmp[], 1)
jne .SKIPTIMERCHECK ; oops, I got something in the meantime (yay, I guess)
jmp short .SENDPKTOUT
.SKIPTIMERCHECK:
; monitor [PKTBUFBUSY] for non-zero ('got reply')
cmp [PKTBUFBUSY], dl    ; dl=0
je short .WAITSOMEMORE
; received something: set the 'dirty' var so I know not to resend my pkt
mov [BYTEVAR], dh       ; dh=1
%if DBG = 2
mov [DBGCOLOR], byte 1   ; DBG, BLUE (pkt rcvd)
mov [DBGVALUE], byte 'r'
call VGADBG
%endif
; received something: check that protover, reqid and flopid are matching
mov si, PKT_PROTOVER
mov di, HDR_PROTOVER
mov cx, 5   ; compare 5 words (10 bytes, ie. PROTOVER+FLOPID+REQID)
repe cmpsw  ; compare CX words at ES:DI and DS:SI
jcxz .CHECKCKSUM  ; is CX zero (success)?
; flag the pkt buffer as 'available' and continue waiting
%if DBG = 2
mov [DBGCOLOR], byte 0x40  ; DEBUG ONLY (RED)
mov [DBGVALUE], byte 'H'
call VGADBG
%endif
mov [PKTBUFBUSY], dl    ; dl=0
jmp short .WAITSOMEMORE
.CHECKCKSUM:
; compute and validate csum
call COMPUTEPKTCSUM
cmp bx, [PKT_CSUM]
je short .SENDRET
%if DBG = 2
mov [DBGCOLOR], byte 0x40 ; DEBUG ONLY (RED)
mov [DBGVALUE], byte 'C'  ; DEBUG ONLY (RED)
call VGADBG
%endif
jmp short .WAITSOMEMORE   ; if packet invalid, keep waiting
.SENDRETERR:
stc ; set CF (csum mismatch)
.SENDRET:
; restore registers and return to caller
pop es
pop ds
pop di
pop si
pop dx
pop cx
pop bx
pop ax
; set ah=0x80
mov ah, 0x80
ret

%if DBG != 0
; output debug data to vga
LASTCOL dw 0
DBGVALUE db 0
DBGCOLOR db 0
VGADBG:
add [cs:LASTCOL], word 2
and [cs:LASTCOL], word 127
push bx
push dx
push es
mov bx, 0xB800
mov es, bx              ; es = vga segment
mov bx, [cs:LASTCOL]
mov dx, [cs:DBGVALUE]
mov [es:bx + (12 * 160)], dx   ; bg color + val
pop es
pop dx
pop bx
ret
%endif

; ============================================================================
; === RELAY TO PREV HANDLER (DOS OR BIOS) ====================================
; ============================================================================
RELAYTOPRVHANDLERDOS:      ; TSR code jumps here when I want to hand control
jmp far [cs:PRVHANDLERDOS] ; to the previous DOS handler
RELAYTOPRVHANDLERBIOS:     ; TSR code jumps here when I want to hand control
jmp far [cs:PRVHANDLERBIOS]; to the previous int 13h handler

; ============================================================================
; === THIS IS WHERE THE TSR STARTS WHEN CALLED BY DOS ========================
; ============================================================================
INTHANDLERDOS:
cmp dl, [cs:DRIVEID]            ; is DL pointing at my drive?
jne short RELAYTOPRVHANDLERDOS  ; not for me, let original handler take care

; ============================================================================
; === THIS IS WHERE THE TSR STARTS WHEN CALLED BY AN INTERRUPT CALL ==========
; ============================================================================
INTHANDLERBIOS:
cmp dl, [cs:DRIVEID]            ; is DL pointing at my drive?
jne short RELAYTOPRVHANDLERBIOS ; not for me, let original handler take care

; === If I am here, then I will handle this request myself ===================

; reset CFLAG stored on stack (assume success)
push bp    ; there are several ways to achieve this, I initiated a discussion
mov bp, sp ; with some interesting replies on alt.lang.asm - see the thread
           ; "How to modify values placed on the stack?" (27 Sep 2019)
and [bp+6], word 0xFFFE ; stack contains bp, ip, cs, flags
pop bp ; restore BP to its original value

; save stack pointers and switch to my own stack block so pktdrvr is happy
mov [cs:ORIGSS], ss
mov [cs:ORIGSP], sp
push cs
pop ss  ; I should do that only after a CLI, but here I am inside an
        ; int handler, so interrupts are disabled already

; pre-fill pkt hdr with registers, as seen at entry point
mov sp,HDR_DX + 2 ; +2 due to "push dx" equals "--sp = dx"
push dx           ; mov [cs:HDR_DX], dx
push cx           ; mov [cs:HDR_CX], cx
push bx           ; mov [cs:HDR_BX], bx
push ax           ; mov [cs:HDR_AX], ax

mov sp, PROGSTART + (STACKSIZE - 2)

; enable interrupts - this is good for two reasons: allows nested interrupts,
; and makes it possible to use the PIT counter for timeout detection
sti

; clear direction flag, so all rep-like ops always move forward
cld

%if DBG != 0
; print int called (AH) on screen (YELLOW)
mov [cs:DBGCOLOR], byte 14
mov [cs:DBGVALUE], ah
add [cs:DBGVALUE], byte '@'
call VGADBG
%endif

; identify the int 13h query
or ah, ah        ; test for ah == 0 (byte shorter than cmp ah, 0)
jz short HANDLERDONE   ; special case: RESET always succeeds, ah=0, nothing to do
dec ah ; cmp ah, 0x01
jne short ACTION_NOT_STATUSLASTOP
; int 13h, ah=1h
mov ah, [cs:LASTOPSTATUS] ; load AH with last status op
jmp short HANDLERDONE
ACTION_NOT_STATUSLASTOP:
dec ah ; cmp ah, 0x02
je short ACTION_READ
dec ah ; cmp ah, 0x03
je short ACTION_WRITE
; unrecognized function -> let the server worry about it
call PKTDRVR_SEND     ; send frame and preset ah=0x80 ("timeout, not read")
jc short HANDLERDONE  ; abort on failure
jmp short HANDLERDONE_GOTPKT


; process the query - set ah to 0 on success errno otherwise, then jmp HANDLERDONE

ACTION_READ: ; int 13h,ah=2h: al=sectors_to_read, ch=cyl, cl=sect, dh=head
and al, 0xff ; ah=0 and test al for zero (query to rd/wr 0 sects -> success)
jz HANDLERDONE
mov [cs:HDR_SECTNUM], ah ; zero out HDR_SECTNUM (ah=0 here, and that's a byte shorter than using byte 0)
.ACTION_READ_NEXTSECT:
cmp al, [cs:HDR_SECTNUM]  ; do I have any sectors left for read?
je short HANDLERDONE_GOTPKT
call PKTDRVR_SEND     ; send frame and preset ah=0x80 ("timeout, not read")
; abort on failure
jnc short .ACTION_READ_GOTPKT
mov al, [cs:HDR_SECTNUM] ; AL tells "HOW MANY SECTORS HAVE BEEN TRANSFERRED"
jmp short HANDLERDONE
.ACTION_READ_GOTPKT:
; did I get a server-side error? (PKT_AH != 0)
test [cs:PKT_AX+1], byte 0xff
jnz short HANDLERDONE_GOTPKT
; all good. write result to es:bx + 512*sect
push es
push ds
push cx
push cs ; ds = cs
pop ds
; recompute the destination pointer to account for sector id displacement
call COMMON_READWRITE_COMPUTE_ES_CX_SI_DI ; ES=HDR_SECTNUM * 32, CX=256, SI=PKT_DATA, DI=BX
rep movsw            ; copy CX words from DS:SI to ES:DI (destroys CX, SI, DI)
inc byte [HDR_SECTNUM]; inc without CS prefix - do it NOW, before DS changes again!
pop cx
pop ds
pop es
; proceed to next sector
jmp short .ACTION_READ_NEXTSECT

; jump here once local processing is done: either to HANDLERDONE_GOTPKT if
; PKT_DMAC contains a valid server answer, or straight to HANDLERDONE
; otherwise. In the latter case, ah is expected to contain a valid errno.
; these subroutines can appear to be at an odd place in the code - this is
; to favor usage of short jumps to it.
HANDLERDONE_GOTPKT:
cli ; disable interrupts - I will modify stack pointers so I can't be bothered
push cs
pop ss ; I should do that only after a CLI
mov sp,PKT_AX
pop ax ; mov ax, [cs:PKT_AX]
pop bx ; mov bx, [cs:PKT_BX]
pop cx ; mov cx, [cs:PKT_CX]
pop dx ; mov dx, [cs:PKT_DX]
HANDLERDONE:
cli ; disable interrupts - I will modify stack pointers so I can't be bothered
; save AH to [LASTOPSTATUS]
mov [cs:LASTOPSTATUS], ah
; switch back to original stack
mov ss, [cs:ORIGSS]
mov sp, [cs:ORIGSP]
; set CF in FLAGS on stack if ah != 0
or ah, ah    ; test for zero
jz short .ALLESGUT
push bp
mov bp, sp
or [bp+6], word 0x0001 ; stack contains bp, ip, cs, flags
pop bp ; restore BP to its original value
.ALLESGUT:
iret ; processing done, return from interrupt

ACTION_WRITE: ; int 13h, ah=3h (write AL sectors at CHS CH:DH:CL from ES:BX)
and al, 0xff ; ah=0 and test al for zero (query to rd/wr 0 sects -> success)
jz short HANDLERDONE
mov [cs:HDR_SECTNUM], ah ; zero out HDR_SECTNUM (ah=0 here, and that's a byte shorter than using byte 0)
.ACTION_WRITE_NEXTSECT:
cmp al, [cs:HDR_SECTNUM]  ; do I have any sectors left for read?
je short HANDLERDONE_GOTPKT
; copy data from ES:BX + 512*sect to PKT_DATA
push es
push ds
push cx
; recompute the destination pointer to account for sector id displacement
call COMMON_READWRITE_COMPUTE_ES_CX_SI_DI ; ES=HDR_SECTNUM * 32, CX=256, SI=PKT_DATA, DI=BX
xchg si, di          ; swap si <--> di  (SI=BX, DI=PKT_DATA)
push es              ; ds = es
pop ds
push cs              ; es = cs
pop es
rep movsw            ; copy CX words from DS:SI to ES:DI (destroys CX, SI, DI)
pop cx
pop ds
pop es
call PKTDRVR_SEND     ; send frame and preset ah=0x80 ("timeout, not read")
; abort on failure
jnc short .ACTION_WRITE_GOTPKT
mov al, [cs:HDR_SECTNUM] ; AL tells "HOW MANY SECTORS HAVE BEEN TRANSFERRED"
jmp short HANDLERDONE
.ACTION_WRITE_GOTPKT:
; did I get a server-side error? (PKT_AH != 0)
test [cs:PKT_AX+1], byte 0xff
jnz short HANDLERDONE_GOTPKT
; proceed to next sector
inc byte [cs:HDR_SECTNUM]
jmp short .ACTION_WRITE_NEXTSECT

; FUNCTION BELOW IS USED BY BOTH ACTION_READ AND ACTION_WRITE TO RECALCULATE
; ES SO IT POINTS TO A SECTOR POSITION IN A BUFFER
; es = ([cs:HDR_SECTNUM] * 32)
; cx = 512 / 2
; di = bx
; si = PKT_DATA
COMMON_READWRITE_COMPUTE_ES_CX_SI_DI:
push ax
mov al, [cs:HDR_SECTNUM] ; load al with sector id
mov cl, 32
mul cl                   ; ax = al * 32
push es                  ; es += ((COUNTER * 512) / 16)
pop cx                   ; es += ((COUNTER * 512) / 16)
add ax, cx               ; es += ((COUNTER * 512) / 16)
push ax                  ; es += ((COUNTER * 512) / 16)
pop es                   ; es += ((COUNTER * 512) / 16)
mov cx, 256
mov di, bx               ; reuse offset, sector count is handled by segment change
mov si, PKT_DATA         ; origin (DS:SI) is set to CS:PKT_DATA
pop ax
ret


; === TSR ENDS HERE ==========================================================

; ============================================================================
; === THIS IS WHERE THE PROGRAM STARTS WHEN EXECUTED FROM COMMAND LINE =======
; ============================================================================
SRVSIDEQUERIES db "deilnr"  ; arguments that are meant for a srv-side query
SRVSIDEQUERIESLEN equ 6
PROGSTART:

cld    ; clear direction flag so all lodsb-like ops move forward

; first of all - initialize HDR_* fields to defaults using HDR_TEMPLATE
mov cx, (HDR_END-HDR_BEGIN)/2   ; /2 because I will copy WORDS, NOT BYTES
push ds  ; cs == ds already (because TINY model)
pop es   ; now cs == ds == es (in theory DOS did it already, but who knows)
mov di, HDR_BEGIN
mov si, HDR_TEMPLATE
rep movsw      ; [ES:DI+=2] = word [DS:SI+=2], CX times

; now copy the cksum routine to its final place (memory optimization makes me
; do crazy things)
mov cx, (1+COMPUTEPKTCSUM_TEMPLATE_END-COMPUTEPKTCSUM_TEMPLATE)/2 ; +1 because it might not be word-sized
mov di, COMPUTEPKTCSUM ; cs == ds == es already (see above)
mov si, COMPUTEPKTCSUM_TEMPLATE
rep movsw      ; [ES:DI+=2] = word [DS:SI+=2], CX times

; same story for the timer routine
mov cx, (1+GETCURTICK_TEMPLATE_END-GETCURTICK_TEMPLATE)/2 ; +1 because it might not be word-sized
mov di, GETCURTICK ; cs == ds == es already (see above)
mov si, GETCURTICK_TEMPLATE
rep movsw      ; [ES:DI+=2] = word [DS:SI+=2], CX times

; parse arguments (ignore spaces)
xor cx, cx
mov cl, [80h]
cmp cl, 32      ; is arg len > 32 ?
ja HELP         ; must be invalid, go to help
or cx, cx       ; is arg len 0 ?
jz HELP         ; if so, skip this check and go to help right away
mov si, 81h     ; otherwise scan argument for anything that is not a space
.nextbyte:
lodsb  ; load byte at DS:[SI] into AL, increment SI
; convert AL into lower case for further matching
cmp al, 'A'
jb short .locasegood
cmp al, 'Z'
ja short .locasegood
or al, 0x20  ; set char to upcase
.locasegood:
; match action
cmp al, 'u'  ; 'u' -> jump to unload
je UNLOADTSR
cmp al, 'a'  ; 'a' -> jump to install (set drive to A:)
mov [DRIVEID], byte 0
je INSTALLTSR
cmp al, 'b'  ; 'b' -> jump to install (set drive to B:)
mov [DRIVEID], byte 1
je INSTALLTSR
cmp al, 's'  ; 's' -> jump to status
je DISPLAYSTATUS
; test for server-side queries
mov cx, SRVSIDEQUERIESLEN
mov di, SRVSIDEQUERIES
repne scasb   ; cmp al, [ES:DI++]  (repeat CX times or until match)
je short SERVERSIDEQUERY ; do we have a match? yes -> srvside query
; last test - is al a space?
cmp al, ' '
loopz .nextbyte ; if a non-space char is present, print help
; no match? go to hell(p)
jmp HELP

; ============================================================================
; === EXECUTE A SERVER-SIDE ONLY QUERY =======================================
; ============================================================================
SERVERSIDEQUERY:
call FINDTSR                ; TSR seg in ES now
jc NOTINSTALLED             ; abort if not found
call SENDSRVQUERY
mov ax, 0x4C00
rcl al, 1    ; set al to 1 if CF set (srv query failed)
int 21h

; ============================================================================
; === Abort installation because TSR already loaded ==========================
; ============================================================================
ALREADYINSTALLED:
mov ah, 0x09
mov dx, STR_ALREADYLOADED
int 21h
; terminate
mov ax, 0x4C02
int 21h

; ============================================================================
; === STUPID INT 13H HANDLER THAT ALWAYS FAILS ===============================
; ============================================================================
; this is used when installing the TSR through int 2Fh,ah=13h, there is a
; short time when I need to set the vector to any valid jump address in case
; a 13h interrupt would fire.
DUMMYHANDLER:
mov ax, 0x0100  ; ah=1 failure  al=0 in case it was a read query
; set CF on stack
push bp
mov bp, sp
or [bp+6], word 1   ; stack contains BP, IP, CS and flags
pop bp
iret

; ============================================================================
; === INSTALL TSR ============================================================
; ============================================================================
INSTALLTSR:
; am I hooked already?
call FINDTSR ; returns cfg block in ES:BX, or CF on error
jnc short ALREADYINSTALLED
; not installed yet - save previous handler
mov [PRVHANDLERBIOS], bx
mov [PRVHANDLERBIOS+2], es
; find packet driver
call FINDPKTDRVR ; returns pktdrvr ptr in ES:BX, CF set on error (not found)
jnc short .PACKETDRVRFOUND
mov ah, 0x09
mov dx, STR_PKTDRVRNOTFOUND
int 21h
mov ax, 0x4C04  ; terminate with error
int 21h
.PACKETDRVRFOUND:
; write packet driver addr (ES:BX) to PKTDRVR
mov [PKTDRVR], bx
mov [PKTDRVR+2], es
; init packet driver (register a handle)
call PKTDRVRREGISTER
jnc short .PKTDRVINITOK
; init failed
mov ah, 0x09
mov dx, STR_PKTDRVRINITFAIL
int 21h
mov ax, 0x4C05
int 21h
.PKTDRVINITOK: ; init ok, handle acquired
; load local MAC address
mov ah, 6        ; AH=6 is get_addr()
mov bx, [PKTDRVRHANDLE]
push cs  ; es = cs
pop es
mov di, HDR_SMAC     ; where to write the MAC to
mov cx, 6            ; expected length (ethernet = 6 bytes)
; simulate int
pushf
cli
call far [PKTDRVR]
; discover local server (and ask for currently inserted floppy)
mov [HDR_DMAC], word 0xffff
mov [HDR_DMAC+2], word 0xffff
mov [HDR_DMAC+4], word 0xffff
mov [PKT_AX], byte 0    ; ah = 0   'disk reset'
mov [PKT_DX], byte 0    ; dl = disk number (server doesn't care really)
call PKTDRVR_SEND
jnc .SERVERFOUND
; ERROR - server unreachable
call PKTDRVR_RELEASE  ; release handle
mov ah, 0x09
mov dx, STR_SERVERUNREACHABLE
int 0x21
mov ax, 0x4C01 ; quit with error
int 0x21
.SERVERFOUND:
; print text message from server (pkt_data + 0x100)
mov ah, 0x09
mov dx, PKT_DATA + 0x100
int 0x21
; print a cr/lf
mov ah, 0x09
mov dx, STR_CRLF
int 0x21
; save current flopid (server sends it in pkt_data as an answer to reset)
mov ax, [PKT_DATA]
mov [HDR_FLOPID], ax
mov ax, [PKT_DATA+2]
mov [HDR_FLOPID+2], ax
mov ax, [PKT_DATA+4]
mov [HDR_FLOPID+4], ax
mov ax, [PKT_DATA+6]
mov [HDR_FLOPID+6], ax
; save server's MAC to header template
mov ax, [PKT_SMAC]
mov [HDR_DMAC], ax
mov ax, [PKT_SMAC+2]
mov [HDR_DMAC+2], ax
mov ax, [PKT_SMAC+4]
mov [HDR_DMAC+4], ax
; hook myself into the int 13h DOS chain
mov dx, DUMMYHANDLER ; set ES:BX and DS:DX to the dummyhandler to avoid
mov bx, dx           ; horrible things to happen in case someone fires an
push cs              ; int 13h before I'm done
pop ds
push cs
pop es
mov ah, 0x13         ; int 2Fh, ah=0x13 = set/get int 13h vector (DOS 3.3+)
int 0x2f ; prv handler at ds:dx now, BIOS routine at es:bx
mov [cs:PRVHANDLERDOS], dx     ; save the original handler as known by int 2f
mov [cs:PRVHANDLERDOS+2], ds
mov dx, INTHANDLERDOS          ; set DS:DX to my own (new) handler
push cs
pop ds
mov ah, 0x13                   ; call int 2Fh,ah=13h again to finish the setup
int 0x2f
push cs     ; restore DS to a sane value (DS = CS)
pop ds
; hook myself into int 13h (classic approach, but does not make DOS 3.3+ use
; the new vector - this is why the above int 2f mess is necessary)
mov ax, 0x2513         ; DOS 1+, AH=25h, AL=intnum, DS:DX=handler
mov dx, INTHANDLERBIOS ; DS is already same as CS
int 21h
; release my environment block (env seg is at offset 0x2C of the TSR's PSP)
mov es, [cs:0x2C]
mov ah, 0x49    ; free memory (DOS 2+) - ES must contain segment to free
int 21h
; print message ("tsr loaded")
mov ah, 0x09
mov dx, STR_LOADED
int 21h
; turn into TSR, trimming transient code - ie. everything below PROGSTART+STACKSIZE
mov ax, 0x3100  ; AH=31h (DOS 2+,"TSR")  AL=0 (exitcode)  DX=num of paragraphs to keep resident
mov dx, (0x100 + 15 + (PROGSTART + STACKSIZE - TSRBEGIN)) / 16   ; make sure number of paragraphs is enough
int 21h

; ============================================================================
; === FIND PACKET DRIVER =====================================================
; ============================================================================
; scan int vectors 60h..80h looking for a packet drvr sig. returns found
; address in ES:BX, or set CF on failure.
FINDPKTDRVR:
mov al, 0x5F   ; initial vect number to scan - 1
.TRYNEXTVECT:
inc al
cmp al, 0x80
ja short .PKTDRVRNOTFOUND     ; don't look past int 80h
mov ah, 0x35   ; AH=35h (GET INT VECT, DOS 2+) - vect is in AL already
int 21h        ; vector is at ES:BX now
; look for the 'PKT DRVR' sig, ie. 4x WORDS: 0x4B50 0x2054 0x5244 0x5256
cmp [es:bx+3], word 0x4b50 ; 'PK'
jne short .TRYNEXTVECT
cmp [es:bx+5], word 0x2054 ; 'T '
jne short .TRYNEXTVECT
cmp [es:bx+7], word 0x5244 ; 'DR'
jne short .TRYNEXTVECT
cmp [es:bx+9], word 0x5256 ; 'VR'
jne short .TRYNEXTVECT
; FOUND!
clc                     ; clear CF (no error, valid pkt drv ptr in ES:BX)
ret
.PKTDRVRNOTFOUND:
stc                     ; CF set to indicate error
ret

; ============================================================================
; === FIND TSR ===============================================================
; ============================================================================
; looks for ethflop tsr, on success, it will return:
;   TSR's seg in ES (PSP at ES:00, entry point at ES:BX)
; on error, CF is set and ES:BX points to the current int 13h handler
; this function destroys AX, BX, CX, ES and FLAGS
FINDTSR:
; get int 13h vector into ES:BX
mov ax, 0x3513  ; AH=35h (GET INT VECT, DOS 2+), AL=13h (interrupt number)
int 21h         ; ES = segment, BX = offset
; is it me? (look for the 5-bytes 'EFLOP' signature)
lea di, [bx - (INTHANDLERBIOS - STR_SIG)] ; my sig is above int entry point
mov si, STR_SIG
mov cx, 5
cld                ; cmpsb will move forward
repe cmpsb         ; compares CX bytes at ES:DI and DS:SI, CX is 0 if matching
clc                ; assume success
je short .FINDTSRFOUND ; jump if sig matched
stc
.FINDTSRFOUND:
ret

; ============================================================================
; === UNLOAD TSR =============================================================
; ============================================================================
UNLOADTSR:
; findtsr
call FINDTSR                ; TSR seg in ES now
jc NOTINSTALLED             ; abort if not found
; restore previous int 13h handler
push ds                     ; save DS and ES to stack
push es
mov ah, 0x25                  ; SET INT VECTOR (DOS 1+)
mov dx, [es:PRVHANDLERBIOS]   ; DX (offset of new handler)
mov ds, [es:PRVHANDLERBIOS+2] ; DS (seg of new handler)
int 0x21
; inform DOS through int 2F
mov ah, 0x13
mov dx, [es:PRVHANDLERDOS]
mov ds, [es:PRVHANDLERDOS+2]
push dx   ; save DS:DX to stack, will be needed again in a moment
push ds
int 0x2f
; do it again, otherwise the 'BIOS' ptr at es:bx would be a total mess
pop ds
pop dx
int 0x2f
pop es
pop ds                      ; restore my DS and ES from stack
; unregister the packet driver handle
call PKTDRVR_RELEASE
; free TSR seg
mov ah, 0x49    ; free memory (DOS 2+) - ES must contain segment to free
int 21h
jnc short .UNLOADTSRDONE
; otherwise an error occurred
mov ah, 0x09
mov dx, STR_FAILEDFREETSR
int 21h
.UNLOADTSRDONE:
; print msg
mov ah, 0x09
mov dx, STR_UNINSTALLED
int 21h
; terminate
mov ax, 0x4C00
int 21h

; ============================================================================
; === RELEASE PKTDRVR HANDLE =================================================
; ============================================================================
; requires config block segment to be set in ES
; destroys ax and bx
PKTDRVR_RELEASE:
push es
mov ah, 3     ; AH=3 is release_type()
mov bx, [es:PKTDRVRHANDLE]
; simulate an int call
pushf
cli
call far [es:PKTDRVR]
pop es
ret

; ============================================================================
; === REGISTER ETHERTYPE RECEIVING ROUTINE ===================================
; ============================================================================
; requires DS:HDR_ETYPE to contain the ethertype value
; DS:PKTDRVR must contain a valid far pointer to the pktdrvr routine
; returns CF set on error, otherwise sets [PKTDRVRHANDLE] with the handle
PKTDRVRREGISTER:
push ax
push bx
push cx
push dx
push si
push di
push es
; init packet driver (register a handle)
mov ax, 0x0201           ; AH=access_type()   AL=ifclass=1(eth)
mov bx, 0xffff           ; if_type=0xffff (all)
mov dl, 0                ; if_number=0 (first interface available)
mov si, HDR_ETYPE ; DS:SI points to the ethertype val in network byte order
mov cx, 2                ; typelen (ethertype is 16 bits)
push cs                  ; ES:DI must point to the frame-receiving routine
pop es
mov di, PKTDRVR_RECV
; simulate an 'int' call
pushf
cli
call far [PKTDRVR] ; now pkthandle should be in AX, or CF set on error
mov [PKTDRVRHANDLE], ax     ; save my precious handle
pop es
pop di
pop si
pop dx
pop cx
pop bx
pop ax
ret

; ============================================================================
; === HELP SCREEN ============================================================
; ============================================================================
HELP:
mov ah, 0x09
mov dx, STR_HELP
int 21h
; terminate
mov ax, 0x4C01
int 21h

; ============================================================================
; === Abort installation because TSR already loaded ==========================
; ============================================================================
NOTINSTALLED:
mov ah, 0x09
mov dx, STR_NOTINSTALLED
int 21h
; terminate
mov ax, 0x4C03
int 21h

; ============================================================================
; === DISPLAY TSR STATUS =====================================================
; ============================================================================
DISPLAYSTATUS:
call FINDTSR                ; TSR seg in ES now
jc short NOTINSTALLED       ; abort if not found
mov ah, 0x09
mov dx, STR_TSRISINSTALLEDAS
int 0x21
mov ah, 0x02
mov dl, [es:DRIVEID]
add dl, 'A'
int 0x21
mov ah, 0x02
mov dl, ':'
int 0x21
mov ah, 0x09
mov dx, STR_CRLF
int 0x21
; get server status and quit
call SENDSRVQUERY
mov ax, 0x4C00
int 0x21

; ============================================================================
; === SEND CONTROL QUERY TO SERVER AND PRINT RESULT ==========================
; ============================================================================
; es must be set to the tsr's config block
; returns with CF set on error, clear on success
SENDSRVQUERY:
; make sure that DS = CS
push cs
pop ds
; copy hdr area from TSR
mov cx, (HDR_END - HDR_DMAC) / 2
xor bx, bx
.COPYWORD:
mov ax, [es:HDR_DMAC+bx]
mov [HDR_DMAC+bx], ax
inc bx
inc bx
loop .COPYWORD
; copy pktdrvr addr
mov ax, [es:PKTDRVR]
mov [PKTDRVR], ax
mov ax, [es:PKTDRVR+2]
mov [PKTDRVR+2], ax
; set ethertype to 'control'
mov [HDR_ETYPE], word 0xDCEF   ; 0xEFDC in net byte order
; register a handle for control ethertype
call PKTDRVRREGISTER
jnc short .PKTDRVINITOK
; pktdrv init failed
mov ah, 0x09
mov dx, STR_PKTDRVRINITFAIL
int 21h
mov ax, 0x4C05
int 21h
.PKTDRVINITOK: ; init ok, handle acquired
; set reqid to some random value
call GETCURTICK     ; tick val in BL now
mov [HDR_REQID], bl
; copy cmdline len and body to packet data
mov cx, 128       ; copy 128 words (256 bytes)
xor bx, bx
.COPYWORD2:
mov ax, [0x80+bx]
mov [PKT_DATA+bx], ax
inc bx
inc bx
loop .COPYWORD2
; send
call PKTDRVR_SEND
pushf     ; save flags so I can check later if send succeeded
push es
push ds
pop es
call PKTDRVR_RELEASE   ; es must point to my local cfg block
pop es
popf
jnc .GOTANSWER
; err
mov ah, 0x09
mov dx, STR_SERVERUNREACHABLE
int 0x21
stc
ret
; print received answer
.GOTANSWER:
mov ah, 0x09
mov dx, PKT_DATA
int 0x21
; update TSR's FLOPID
mov ax, [PKT_AX]
mov [es:HDR_FLOPID], ax
mov ax, [PKT_BX]
mov [es:HDR_FLOPID+2], ax
mov ax, [PKT_CX]
mov [es:HDR_FLOPID+4], ax
mov ax, [PKT_DX]
mov [es:HDR_FLOPID+6], ax
; end of story
clc
ret

; ============================================================================
; === STRINGS USED BY THE TRANSIENT LOADER ===================================
; ============================================================================
; (no need to declare a .data section, tiny model imples DS == CS anyway)
STR_HELP db "ethflop v0.7m - a floppy drive emulator over Ethernet", 13, 10,\
            "Copyright (C) 2019 Mateusz Viste, 2020 Michael Ortmann", 13, 10, 10,\
            "=== USAGE ====================================================================", 13, 10,\
            "ethflop a           installs the ethflop TSR as A:", 13, 10,\
            "ethflop b           installs ethflop as B: (works only if you have a real B:)", 13, 10,\
            "ethflop i DISKNAME  'inserts' the virtual floppy named 'DISKNAME'", 13, 10,\
            "ethflop ip DSKNAME  same as 'i', but the inserted floppy is WRITE PROTECTED", 13, 10,\
            "ethflop r OLD NEW   renames virt. floppy 'OLD' to 'NEW'", 13, 10,\
            "ethflop e           'ejects' currently loaded virtual floppy", 13, 10,\
            "ethflop nSZ DSKNAME creates a new virtual floppy DSKNAME, SZ kB big", 13, 10,\
            "                    run 'ethflop n' for the list of available formats", 13, 10,\
            "ethflop l           displays the list of available virt. floppies", 13, 10,\
            "ethflop d DISKNAME  DELETES virt. floppy named DISKNAME - BE CAREFUL!", 13, 10,\
            "ethflop s           displays current status of the ethflop TSR", 13, 10,\
            "ethflop u           unloads the ethflop TSR", 13, 10, 10,\
            "=== NOTES ====================================================================", 13, 10,\
            " * Disk names must be 1 to 8 characters long. Only A-Z, 0-9 and '_-' allowed.", 13, 10,\
            " * ethflop requires the presence of an ethflop server on the local network.", 13, 10, 10,\
            "=== LICENSE ==================================================================", 13, 10,\
            "ethflop is published under the terms of the ISC license. See ETHFLOP.TXT.", 13, 10,\
            " $" ; the space here is not meaningless - it enforces an extra LF under FreeDOS
STR_LOADED db "ethflop has been installed$"
STR_ALREADYLOADED db "ERROR: ethflop is already installed$"
STR_NOTINSTALLED db "ERROR: ethflop is not installed or has been overloaded by another ISR$"
STR_FAILEDFREETSR db "ERROR: Failed to free TSR's memory segment$"
STR_UNINSTALLED db "ethflop has been uninstalled$"
STR_PKTDRVRNOTFOUND db "ERROR: no packet driver found$"
STR_TSRISINSTALLEDAS db "ethflop is currently installed as drive $"
STR_PKTDRVRINITFAIL db "ERROR: packet driver initialization failed$"
STR_NO2F db "NOTE: no INT 2Fh,AH=13h support detected$"
STR_SERVERUNREACHABLE db "ERROR: server unreachable$"
STR_CRLF db 13, 10, "$"

; ****************************************************************************
; This is the template for frame's header. It is used at startup to initialize
; the HDR_* fields located in the PSP area to default (sane) values
HDR_TEMPLATE:
.HDR_DMAC db "MONIKA" ; destination (server) MAC (6 bytes)
.HDR_SMAC db "      " ; source (local) MAC (6 bytes)
.HDR_ETYPE dw 0xDDEF  ; ethertype (data = 0xEFDD, control = 0xEFDC)
.HDR_PROTOVER db 1    ; protocol version
.HDR_REQID db 0       ; request's sequence number (answer must have the same)
.HDR_FLOPID dw 0,0,0,0; current virtual floppy id (1st word=0 means none)
.HDR_AX dw 0          ; AX
.HDR_BX dw 0          ; BX
.HDR_CX dw 0          ; CX
.HDR_DX dw 0          ; DX
.HDR_SECTNUM db 0     ; sector number (used for multi-sector READs and WRITEs)
.HDR_FFU db 'X'       ; for future use (word-padding)

; ****************************************************************************
; IMPORTANT: THE FUNCTIONS BELOW ARE NOT TO BE CALLED! THESE ARE TEMPLATES
; THAT ARE COPIED TO PSP AT STARTUP. COMPUTEPKTCSUM AND GETCURTICK MUST BE
; CALLED INSTEAD. THESE ROUTINES SHALL USE EXCLUSIVELY RELATIVE JUMPS,
; OTHERWISE MY CRUDE RELOCATION WILL BREAK THEM!
; ============================================================================
; === CHECKSUM COMPUTATION (CODE MAX 20 BYTES BIG!) ==========================
; ============================================================================
; computes CSUM of packet data starting at PKT_FLOPID, returns CSUM in BX
; destroys BX, CX and SI
COMPUTEPKTCSUM_TEMPLATE:
push ax
mov si, PKT_PROTOVER  ; checksum starts at protover
mov cx, (PKT_CSUM-PKT_PROTOVER)/2  ; this many words (not bytes!)
xor bx, bx     ; bx will contain the resulting csum
.CSUMNEXTWORD:
lodsw          ; AX = [DS:SI], SI += 2
rol bx, 1
xor bx, ax
loop .CSUMNEXTWORD ; repeat CX times (loop is a relative jump, so it's safe)
pop ax
ret
COMPUTEPKTCSUM_TEMPLATE_END:
; ============================================================================
; === GET SHORT TIMER STATUS (CODE MAX 14 BYTES BIG!) =========================
; ============================================================================
; reads the lowest byte of the system timer at 0040:6C and returns it in BL
; destroys BH
GETCURTICK_TEMPLATE:
push ds 
xor bx, bx      ; zero out bx
mov ds, bx      ; ds points to seg 0 now
mov bl, [046Ch] ; read lowest byte of the system 18.2 hz timer
pop ds
ret
GETCURTICK_TEMPLATE_END:


; ****************************************************************************
; the weird shit below would be required if transient size ended up to be
; smaller than TSR stack size - this because the TSR defines its stack area
; at transient program's start.
;ENDOFCODE:
;FILLER times (STACKSIZE - (ENDOFCODE - PROGSTART)) db 'x'
