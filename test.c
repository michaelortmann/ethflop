/*
 * basic test suite for ethflop/ethflopd
 * Copyright (C) 2019 Mateusz Viste
 *
 * to be compiled with Turbo C 2.01
 */

#include <alloc.h> /* farmalloc(), farfree() */
#include <dos.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
  union REGS r;
  struct SREGS sr;
  unsigned short TESTFLAG = 0;
  unsigned char far *sectorbuff;
  int i;

  if (argc == 1) {
    TESTFLAG = 0xffffu;
  } else {
    for (i = 1; i < argc; i++) {
      printf("enabling test #%d\r\n", atoi(argv[i]));
      TESTFLAG |= atoi(argv[i]);
    }
  }

  sectorbuff = farmalloc(512);
  if (sectorbuff == NULL) {
    printf("out of memory\n");
    return(1);
  }

  if (TESTFLAG & 1) {
    printf("TEST 1: DISK RESET... ");
    r.h.ah = 0; /* disk reset */
    r.h.dl = 0; /* A: */
    int86(0x13, &r, &r);
    printf("CF=%d AH=0x%02X\r\n", r.x.cflag, r.h.ah);
    if (r.x.cflag != 0) goto GAMEOVER;
  }

  if (TESTFLAG & 2) {
    printf("TEST 2: READ SECT 0 x1000 times... ");
    for (i = 0; i < 1000; i++) {
      r.h.ah = 2; /* read sector */
      r.h.al = 1; /* one sector */
      r.h.ch = 0; /* cylinder 0 */
      r.h.cl = 1; /* sector 1 (first, sectors starts at 1...) */
      r.h.dh = 0; /* head 0 */
      r.h.dl = 0; /* A: */
      sr.es = FP_SEG(sectorbuff);
      r.x.bx = FP_OFF(sectorbuff);
      int86x(0x13, &r, &r, &sr);
      if (r.x.cflag != 0) break;
    }
    printf("CF=%d AH=0x%02X (done %d times)\r\n", r.x.cflag, r.h.ah, i);
    if (r.x.cflag != 0) goto GAMEOVER;
  }

  printf("ALL GOOD\r\n");

  GAMEOVER:
  farfree(sectorbuff);

  return(0);
}
