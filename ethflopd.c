/*
 * ethflopd is serving files through the ethflop protocol. Runs on Linux.
 *
 * http://ethflop.sourceforge.net
 *
 * ethflopd is distributed under the terms of the ISC License, as listed
 * below.
 *
 * Copyright (C) 2019 Mateusz Viste
 * Copyright (c) 2020 Michael Ortmann
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR
 * IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <arpa/inet.h>       /* htons() */
#include <dirent.h>
#include <errno.h>
#include <endian.h>          /* le16toh(), le32toh() */
#include <fnmatch.h>
#include <linux/if_packet.h>
#include <limits.h>          /* PATH_MAX and such */
#include <net/ethernet.h>
#include <net/if.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>          /* mempcy() */
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <stdint.h>          /* uint16_t, uint32_t */
#include <stdlib.h>          /* realpath() */
#include <time.h>            /* time() */
#include <unistd.h>          /* close(), getopt(), optind */

/* program version */
#define PVER "20191006m"

/* set to 1 to enable DEBUG mode */
#define DEBUG 0

/* set to percentage of simulated packet loss (test purposes only!) */
#define SIMLOSS_INP 0  /* packet is that % likely to get lost at INPUT */
#define SIMLOSS_OUT 0  /* packet is that % likely to get lost at INPUT */

#if DEBUG > 0
#define DBG printf
#else
#define DBG(...)
#endif


struct __attribute__((packed)) FRAME {
  uint8_t dmac[6];
  uint8_t smac[6];
  uint16_t etype;
  uint8_t protover;
  uint8_t reqid;
  char flopid[8];
  uint16_t ax;
  uint16_t bx;
  uint16_t cx;
  uint16_t dx;
  uint8_t sectnum;
  uint8_t ffu;
  uint8_t data[512];
  uint16_t csum;
};

struct cliententry {
  uint8_t mac[6];
  char curflopid[9];
  FILE *fd;       /* open file descriptor to floppy img */
  int ro;         /* read-only flag */
  int sectcount;  /* total count of sectors on floppy */
  int chs_sectspertrack;
  int chs_totheads;
  short diskchangeflag; /* 0=disk not changed, 1=new disk in drive */
  struct cliententry *next;
};


static const struct {
  unsigned char md;        /* media descriptor */
  unsigned char secttrack; /* sectors per track (max. 62) */
  unsigned char cylinders; /* cylinders (or tracks per side, max. 255) */
  unsigned char heads;     /* heads (sides) */
  unsigned char maxRootEntries; /* max number of FAT12 root entries */
  unsigned char clustersz;      /* cluster size, in sectors (FAT12 supports up to 4084 clusters) */
  unsigned char fatsz;          /* single FAT size, in sectors */
  int totsectors;               /* total sectors count */
  char *description;            /* human description, used for the help message */
  /*              MD  sect trk hd root clustsz fatsz totsectors */
} FDPARMS[] = {{0xFD,  9,  40, 2, 112,     2,    2,       720, "360K (1983)"},
               {0xF9,  9,  80, 2, 112,     2,    3,      1440, "720K (1986)"},
               {0xF9, 15,  80, 2, 224,     1,    7,      2400, "1.2M (1984, IBM AT)"},
               {0xF0, 18,  80, 2, 224,     1,    9,      2880, "1.44M, the classic 3.5\" floppy since 1987"},
               {0xF0, 21,  80, 2,  16,     4,    3,      3360, "1.68M (DMF), big clusters and tiny root!"},
               {0xF0, 21,  82, 2,  16,     4,    3,      3444, "1.72M (DMF), big clusters and tiny root!"},
               {0xF0, 36,  80, 2, 224,     2,    9,      5760, "2.88M, a 1991 invention that never caught on"},
               {0xF0, 60,  80, 2, 224,     4,    8,      9600, "4.8M, custom format"},
               {0xF0, 60, 135, 2, 224,     4,   12,     16200, "8.1M, custom format"},
               {0xF0, 60, 160, 2, 224,     8,    8,     19200, "9.6M, custom format"},
               {0xF0, 62, 250, 2, 224,     8,   12,     31000, "15.5M, custom format"},
               {0xF0, 62, 250, 4, 224,    16,   12,     62000, "31M, custom format"},
               {0x00,  0,   0, 0,   0,     0,    0,         0, ""}}; /* end   */
/* some calculations
 * totsectors = sect * trk * hd
 * numOfClusters = (totsectors - 1 - (2*fatsz)) / clustsz
 * fatsz = (numOfClusters * 1.5) / 512 */

/* the flag is set when ethflopd is expected to terminate */
static sig_atomic_t volatile terminationflag = 0;

static void sigcatcher(int sig) {
  switch (sig) {
    case SIGTERM:
    case SIGQUIT:
    case SIGINT:
      terminationflag = 1;
      break;
    default:
      break;
  }
}


/* returns the FDPARMS index matching a size of sz KiB, or -1 if not found */
static int getFDPARMSidbysize(int sz) {
  int i;
  for (i = 0;; i++) {
    if (FDPARMS[i].md == 0) return(-1); /* reached end of list */
    if (FDPARMS[i].totsectors == sz * 2) return(i);
  }
}


/* creates a new 64K header for floppy image in memory, by generating a
 * boot sector and FAT-12 structure. sz is the expected size, in KiB
 * return neg val on error, disk size otherwise */
static int floppygen(unsigned char *dst, int sz) {
  int type;
  /* validate dst */
  if (dst == NULL) return(-1);
  /* translate sz to type id */
  type = getFDPARMSidbysize(sz);
  if (type < 0) return(-1); /* invalid type */
  /* zero out the header */
  memset(dst, 0, 65536);
  /* BOOT SECTOR */
  dst[0] = 0xEB;   /* jmp */
  dst[1] = 0xFE;   /* jmp */
  dst[2] = 0x90;   /* jmp */
  memcpy(dst + 3, "MSDOS5.0", 8);  /* OEM sig */
  dst[0x0B] = 0;   /* bytes per sect LSB */
  dst[0x0C] = 2;   /* bytes per sect MSB */
  dst[0x0D] = FDPARMS[type].clustersz;   /* cluster size, in number of sectors */
  dst[0x0E] = 1;   /* reserved logical sectors (number of sectors before 1st FAT) */
  dst[0x0F] = 0;   /* reserved logical sectors */
  dst[0x10] = 2;   /* num of FATs */
  dst[0x11] = FDPARMS[type].maxRootEntries; /* max num of root dirs, must be multiple of 16 (LSB) */
  dst[0x12] = 0;   /* max num of root dirs, must be multiple of 16 (MSB) */
  dst[0x13] = (uint8_t)(FDPARMS[type].totsectors);        /* total sectors, LSB */
  dst[0x14] = (uint8_t)(FDPARMS[type].totsectors >> 8);   /* tot sectors, MSB */
  dst[0x15] = FDPARMS[type].md; /* media descriptor */
  dst[0x16] = FDPARMS[type].fatsz; /* sectors per FAT, LSB */
  dst[0x17] = 0; /* sectors per FAT, MSB */
  dst[0x18] = FDPARMS[type].secttrack;  /* sectors per track (LSB) */
  dst[0x19] = 0;                       /* sectors per track (MSB) */
  dst[0x1A] = FDPARMS[type].heads;  /* heads count (LSB) */
  dst[0x1B] = 0;                   /* heads count (MSB) */
  /* 1C 1D 1E 1F   - hidden sectors */
  /* 20 21 22 23   - total sectors (extended) */
  /* 24 25         - reserved bytes */
  dst[0x26] = 0x29;              /* 0x29 means that volid, vol label and fsname are present (below) */
  dst[0x27] = (uint8_t)(time(NULL));        /* volume id */
  dst[0x28] = (uint8_t)(time(NULL) >> 8);   /* volume id */
  dst[0x29] = (uint8_t)(time(NULL) >> 16);  /* volume id */
  dst[0x2A] = (uint8_t)(time(NULL) >> 24);  /* volume id */
  memcpy(dst + 0x2B, "NO NAME    ", 11);   /* volume label (2B 2C 2D 2E) */
  memcpy(dst + 0x36, "FAT12   ", 8); /* filesystem name */
  /* 448 bytes of boot code */
  dst[0x1FE] = 0x55;    /* boot sig */
  dst[0x1FF] = 0xAA;    /* boot sig */
  /* empty FAT tables: they simply start by a 3-bytes signature. a FAT sig is
   * two (12 bit) cluster entries: first byte of first entry is a copy of the
   * media descriptor, all other bits are set to 1. */
  dst[0x200] = FDPARMS[type].md; /* 1st FAT starts right after bootsector */
  dst[0x201] = 0xff;
  dst[0x202] = 0xff;
  /* 2nd FAT is at 512 + (sectorsperfat * 512), ie. it follows the 1st FAT table */
  memcpy(dst + 0x200 + (FDPARMS[type].fatsz * 512), dst + 0x200, 3);
  /* */
  return(FDPARMS[type].totsectors * 512);
}

/* acquire a lock file */
static int lockme(const char *lockfile) {
  FILE *fd;
  /* does the file exist? */
  fd = fopen(lockfile, "rb");
  if (fd != NULL) {
    fclose(fd);
    return(-1);
  }
  /* file doesn't seem to exist - create it then */
  fd = fopen(lockfile, "wb");
  if (fd == NULL) return(-1);
  fclose(fd);
  return(0);
}

/* release the lock file */
static void unlockme(const char *lockfile) {
  unlink(lockfile);
}


static struct cliententry *findorcreateclient(struct cliententry **clist, const uint8_t *mac) {
  struct cliententry *e;
  for (e = *clist; e != NULL; e = e->next) {
    if (memcmp(mac, e->mac, 6) == 0) return(e);
  }
  /* nothing found */
  e = calloc(1, sizeof(struct cliententry));
  if (e == NULL) return(NULL); /* out of memory */
  memcpy(e->mac, mac, 6);
  e->next = *clist;
  *clist = e;
  return(e);
}


/* turns a character c into its up-case variant */
static char upchar(char c) {
  if ((c >= 'a') && (c <= 'z')) c -= ('a' - 'A');
  return(c);
}

/* turns a character c into its lo-case variant */
static char lochar(char c) {
  if ((c >= 'A') && (c <= 'Z')) c += ('a' - 'A');
  return(c);
}

/* turns a string into all-upper-case characters, up to n chars max */
static void upstring(char *s, int n) {
  while ((n-- != 0) && (*s != 0)) {
    *s = upchar(*s);
    s++;
  }
}

/* turns a string into all-lower-case characters, up to n chars max */
static void lostring(char *s, int n) {
  while ((n-- != 0) && (*s != 0)) {
    *s = lochar(*s);
    s++;
  }
}

/* generates a formatted MAC address printout and returns a static buffer */
static char *printmac(const unsigned char *b) {
  static char macbuf[18];
  sprintf(macbuf, "%02X:%02X:%02X:%02X:%02X:%02X", b[0], b[1], b[2], b[3], b[4], b[5]);
  return(macbuf);
}

/* converts a CHS tuple into an LBA sector id */
static int chs2lba(int c, int h, int s, int totheads, int sectspertrack) {
  int sectid;
  sectid = (c * totheads + h) * sectspertrack + (s - 1);
  return(sectid);
}

static int process_data(struct FRAME *frame, const unsigned char *mymac, struct cliententry *ce) {
  int sid;

  /* switch src and dst addresses so the reply header is ready */
  memcpy(frame->dmac, frame->smac, 6);  /* copy source mac into dst field */
  memcpy(frame->smac, mymac, 6); /* copy my mac into source field */

  /* decode query type */
  switch(frame->ax >> 8) {
    case 0x00: /* DISK RESET - special case: write current FLOPID in frame's DATA and text message in DATA+100h */
      memcpy(frame->data, ce->curflopid, 8);
      sprintf((char *)(frame->data + 0x100), "server found at %s\r\ncurrent virt. floppy: %s$", printmac(mymac), (ce->curflopid[0] == 0)?"<NONE>":ce->curflopid);
      return(0);
    case 0x02: /* READ SECTOR #sectnum FROM CHS CH:DH:CL*/
    case 0x03: /* WRITE SECTOR #sectnum FROM CHS CH:DH:CL */
      sid = chs2lba(frame->cx >> 8, frame->dx >> 8, frame->cx & 0xff, ce->chs_totheads, ce->chs_sectspertrack) + frame->sectnum;
      if (ce->fd == NULL) {
        fprintf(stderr, "read attempt at empty drive\n");
        frame->ax = 0x4000; /* error 'seek failed' + 0 sectors read/written */
        return(0);
      }
      if (sid >= ce->sectcount) {
        fprintf(stderr, "read attempt past last sector (%d > %d)\n", sid, ce->sectcount - 1);
        frame->ax &= 0x00ff;
        frame->ax |= 0x4000;  /* ah=40h = seek failed */
        return(0);
      }
      if (fseek(ce->fd, sid * 512, SEEK_SET) != 0) {
        fprintf(stderr, "fseek() failed: %s\n", strerror(errno));
        frame->ax &= 0x00ff;
        frame->ax |= 0x4000;  /* ah=40h = seek failed */
        return(0);
      }
      if ((frame->ax >> 8) == 0x03) { /* WRITE OP */
        if (ce->ro != 0) {
          fprintf(stderr, "attempt to write to a write-protected disk\n");
          frame->ax &= 0x00ff;
          frame->ax |= 0x0300;  /* ah=3 = disk is write protected */
          return(0);
        }
        if (fwrite(frame->data, 1, 512, ce->fd) != 512) {
          fprintf(stderr, "fwrite() failure: %s\n", strerror(errno));
          frame->ax &= 0x00ff;
          frame->ax |= 0x0400;  /* ah=4 = sector not found / read error */
          fflush(ce->fd); /* force data to be actually written */
          return(0);
        }
        fflush(ce->fd); /* force data to be actually written */
      } else { /* READ OP */
        if (fread(frame->data, 1, 512, ce->fd) != 512) {
          fprintf(stderr, "fread() failure: %s\n", strerror(errno));
          frame->ax &= 0x00ff;
          frame->ax |= 0x0400;  /* ah=4 = sector not found / read error */
          return(0);
        }
      }
      frame->ax = frame->sectnum + 1; /* al = sectors read, ah = 0 (success) */
      return(0);
    case 0x04: /* VERIFY - in fact this was never meant to actually verify data. always succeeds */
      if (ce->fd == NULL) {
        fprintf(stderr, "verify attempt at empty drive\n");
        frame->ax = 0x4000; /* error 'seek failed' + 0 sectors verified */
        return(0);
      }
      sid = chs2lba(frame->cx >> 8, frame->dx >> 8, frame->cx & 0xff, ce->chs_totheads, ce->chs_sectspertrack);
      /* check how many sectors are valid */
      if (sid + (frame->ax & 0xff) > ce->sectcount) {
        int validsectors = (ce->sectcount - sid) + 1;
        if (validsectors < 0) validsectors = 0;
        frame->ax = 0x4000 | validsectors; /* error 'seek failed' + validsectors verified */
        return(0);
      }
      frame->ax &= 0x00ff;  /* al = sectors verified, ah = 0 (success) */
      return(0);
    case 0x15: /* GET DISK TYPE */
      /* this routine is buggy - it returns AH=0 on success, while RBIL
       * says that success is indicated by CF=0 but AH should report a 0x02
       * code in AH... I can't do this sadly because ethflop assumes ah=0 for
       * success, and would set CF for any other value */
      if (ce->fd == NULL) {
        frame->ax &= 0x00ff;
        frame->ax |= 0x4000; /* ah=31h - no media in drive */
        return(0);
      }
      frame->ax &= 0x00ff;
      frame->cx = 0;  /* number of sectors, high word */
      frame->dx = ce->sectcount; /* number of sectors, low word */
      return(0);
    case 0x16: /* DETECT DISK CHANGE */
      frame->ax &= 0x00ff;
      if (ce->diskchangeflag != 0) {
        frame->ax |= 0x0600;   /* AH=6 - change line active */
        ce->diskchangeflag = 0; /* reset the flag so it's reported only once */
      }
      return(0);
    case 0x20: /* GET CURRENT MEDIA FORMAT */
      if (ce->fd == NULL) {
        frame->ax &= 0x00ff;
        frame->ax |= 0x3100; /* set AH to error "media not present" */
        return(0);
      }
      if (ce->sectcount == 1440) {
        frame->ax = 0x0003; /* AH=0 (success), AL=media type is 720K */
        return(0);
      }
      if (ce->sectcount == 2880) {
        frame->ax = 0x0004; /* AH=0 (success), AL=media type is 1.44M */
        return(0);
      }
      if (ce->sectcount == 5760) {
        frame->ax = 0x0006; /* AH=0 (success), AL=media type is 2.88M */
        return(0);
      }
      if (ce->sectcount == 720) {
        frame->ax = 0x000C; /* AH=0 (success), AL=media type is 360K */
        return(0);
      }
      if (ce->sectcount == 2400) {
        frame->ax = 0x000D; /* AH=0 (success), AL=media type is 1.2M */
        return(0);
      }
      frame->ax &= 0x00ff;
      frame->ax |= 0x3200;  /* ah=30h = drive does not support media type */
      fprintf(stderr, "unable to recognize media type (%d sectors)\n", ce->sectcount);
      return(0);
  }

  /* set ah to error 01 */
  frame->ax &= 0x00ff;
  frame->ax |= 0x0100;
  return(0);
}


/* parse data looking for a cmd, arg and arg2. returns number of arguments, or -1 on error */
static int parseargs(char *cmd, int cmdsz, char *arg, char *arg2, int argsz, const char *data) {
  int i, l, arglen = 0, arglen2 = 0, cmdlen = 0;
  int gotcmd = 0, gotarg = 0;
  l = data[0];
  /* printf("l=%d\n", l); */
  for (i = 1; i <= l; i++) {
/*    printf("i=%d ; data[i]='%c'\n", i, data[i]); */
    if (data[i] == ' ') {
      if (cmdlen > 0) gotcmd = 1;
      if (arglen > 0) gotarg = 1;
      if (arglen2 > 0) break;
      continue; /* skip spaces */
    }
    if (gotcmd == 0) {
      cmd[cmdlen++] = data[i];
    } else if (gotarg == 0) {
      arg[arglen++] = data[i];
    } else {
      arg2[arglen2++] = data[i];
    }
    if (cmdlen > cmdsz) return(-1);
    if (arglen > argsz) return(-1);
    if (arglen2 > argsz) return(-1);
  }
  cmd[cmdlen] = 0;
  arg[arglen] = 0;
  arg2[arglen2] = 0;
  fprintf(stderr, " cmd='%s' arg='%s' arg2='%s'\n", cmd, arg, arg2);
  if (arglen2 > 0) return(3);
  if (arglen > 0) return(2);
  if (cmdlen > 0) return(1);
  return(0);
}

static int validatediskname(const char *n) {
  int i;
  if ((n == NULL) || (*n == 0)) return(-1);
  for (i = 0; n[i] != 0; i++) {
    if (i == 8) return(-1);
    if ((n[i] >= 'a') && (n[i] <= 'z')) continue;
    if ((n[i] >= 'A') && (n[i] <= 'Z')) continue;
    if ((n[i] >= '0') && (n[i] <= '9')) continue;
    if (n[i] == '_') continue;
    if (n[i] == '-') continue;
    if (n[i] == '&') continue;
    return(-1);
  }
  return(0);
}

static const struct cliententry *findcliententrybywritelock(const struct cliententry *clist, const char *dname) {
  while (clist != NULL) {
    if ((clist->ro == 0) && (strcmp(clist->curflopid, dname) == 0)) return(clist);
    clist = clist->next;
  }
  return(NULL);
}

static const struct cliententry *findcliententrybylock(const struct cliententry *clist, const char *dname) {
  while (clist != NULL) {
    if (strcmp(clist->curflopid, dname) == 0) return(clist);
    clist = clist->next;
  }
  return(NULL);
}

static void disk2fullpath(char *fullname, int fullnamesz, const char *storagedir, const char *dname) {
  char dnamelo[64];
  /* validate */
  fullname[0] = 0;
  if (((unsigned int)fullnamesz < strlen(storagedir) + strlen(dname) + 2)) {
    fprintf(stderr, "fullnamesz too short @%d\n", __LINE__);
    return;
  }
  /* convert dname to lowercase */
  snprintf(dnamelo, sizeof(dnamelo), "%s", dname);
  lostring(dnamelo, sizeof(dnamelo));
  /* compute resulting full path name */
  snprintf(fullname, fullnamesz, "%s/%s.img", storagedir, dnamelo);
}

static int imgdirfilter(const struct dirent *d) {
  if (strlen(d->d_name) > 12) return(0);
  if (d->d_type == DT_DIR) return(0);
  if (fnmatch("*.img", d->d_name, 0) != 0) return(0);
  return(1);
}

/* returns 0 if file f does not exist, 1 otherwise */
static int fileexists(const char *f) {
  FILE *fd;
  fd = fopen(f, "rb");
  if (fd == NULL) return(0);
  fclose(fd);
  return(1);
}

static int process_ctrl(struct FRAME *frame, const unsigned char *mymac, const char *storagedir, struct cliententry *ce, struct cliententry *clist) {
  int argc;
  char cmd[8], arg[16], arg2[16];
  char fullname[256], fullname2[256];
  const struct cliententry *sce;

  /* switch src and dst addresses so the reply header is ready */
  memcpy(frame->dmac, frame->smac, 6);  /* copy source mac into dst field */
  memcpy(frame->smac, mymac, 6); /* copy my mac into source field */

  /* parse command list */
  argc = parseargs(cmd, sizeof(cmd) - 1, arg, arg2, sizeof(arg) - 1, (char *)frame->data);
  lostring(cmd, sizeof(cmd));
  upstring(arg, sizeof(arg));
  upstring(arg2, sizeof(arg2));

  if (argc < 1) {
    fprintf(stderr, "illegal query from %s\n", printmac(ce->mac));
    return(-1);
  }

  /* clear out pkt data */
  memset(frame->data, '*', 512);

  if (strcmp(cmd, "s") == 0) {
    sprintf((char *)(frame->data), "server is at %s\r\ncurrent virt. floppy: %s%s$", printmac(mymac), (ce->curflopid[0] == 0)?"<NONE>":ce->curflopid, (ce->ro == 0)?"":" (write-protected)");
    goto DONE;
  }

  if ((strcmp(cmd, "i") == 0) || (strcmp(cmd, "ip") == 0)) {
    int i;
    if (arg[0] == 0) {
      sprintf((char *)(frame->data), "ERROR: you must specify a diskname$");
      goto DONE;
    }
    if (validatediskname(arg) != 0) {
      sprintf((char *)(frame->data), "ERROR: specified disk name is invalid$");
      goto DONE;
    }
    if (ce->fd != NULL) {
      sprintf((char *)(frame->data), "ERROR: you must first eject your current virtual floppy (%s)$", ce->curflopid);
      goto DONE;
    }
    sce = findcliententrybywritelock(clist, arg);
    if (sce != NULL) {
      sprintf((char *)(frame->data), "ERROR: disk '%s' is already write-locked by %s'$", arg, printmac(sce->mac));
      goto DONE;
    }
    /* try loading the disk image */
    disk2fullpath(fullname, sizeof(fullname), storagedir, arg);
    if (strcmp(cmd, "ip") == 0) {
      ce->ro = 1;
      ce->fd = fopen(fullname, "rb");
    } else {
      ce->ro = 0;
      ce->fd = fopen(fullname, "r+b");
    }
    if (ce->fd == NULL) {
      sprintf((char *)(frame->data), "ERROR: disk %s not found$", arg);
      goto DONE;
    }
    /* good */
    fseek(ce->fd, 0, SEEK_END);
    ce->sectcount = (int)ftell(ce->fd) / 512;
    /* find out the type of floppy */
    i = getFDPARMSidbysize(ce->sectcount / 2);
    if (i < 0) {
      fclose(ce->fd);
      ce->fd = NULL;
      sprintf((char *)(frame->data), "ERROR: unknown disk format$");
      goto DONE;
    }
    ce->chs_sectspertrack = FDPARMS[i].secttrack;
    ce->chs_totheads = FDPARMS[i].heads;
    strncpy(ce->curflopid, arg, sizeof(ce->curflopid));
    sprintf((char *)(frame->data), "Disk %s loaded (%d KiB%s)$", ce->curflopid, ce->sectcount / 2, (ce->ro == 0)?"":" (write-protected)");
    ce->diskchangeflag = 1;
    goto DONE;
  }

  if (strcmp(cmd, "e") == 0) {
    if (ce->fd == NULL) {
      sprintf((char *)(frame->data), "ERROR: no virtual floppy loaded$");
      goto DONE;
    }
    fclose(ce->fd);
    ce->fd = NULL;
    sprintf((char *)(frame->data), "Disk %s ejected$", ce->curflopid);
    memset(ce->curflopid, 0, sizeof(ce->curflopid));
    goto DONE;
  }

  if (strcmp(cmd, "d") == 0) {
    if (arg[0] == 0) {
      sprintf((char *)(frame->data), "ERROR: you must specify a diskname$");
      goto DONE;
    }
    if (validatediskname(arg) != 0) {
      sprintf((char *)(frame->data), "ERROR: specified disk name is invalid$");
      goto DONE;
    }
    sce = findcliententrybylock(clist, arg);
    if (sce != NULL) {
      sprintf((char *)(frame->data), "ERROR: disk %s is currently being used by %s$", arg, printmac(sce->mac));
      goto DONE;
    }
    /* try removing it */
    disk2fullpath(fullname, sizeof(fullname), storagedir, arg);
    if (unlink(fullname) != 0) {
      sprintf((char *)(frame->data), "ERROR: failed to delete disk %s (%s)$", arg, strerror(errno));
      goto DONE;
    }
    sprintf((char *)(frame->data), "Disk %s has been deleted$", arg);
    goto DONE;
  }

  if (strcmp(cmd, "l") == 0) {
    struct dirent **namelist;
    int n, i;
    char *ptr = (char *)(frame->data);
    n = scandir(storagedir, &namelist, imgdirfilter, alphasort);
    if (n < 0) {
      sprintf(ptr, "ERROR: %s$", strerror(errno));
      goto DONE;
    }
    if (n == 0) ptr += sprintf(ptr, "no virtual floppy disks available");
    for (i = 0; i < n; i++) {
      int t;
      /* replace first dot by a null terminator and turn uppercase */
      for (t = 0; namelist[i]->d_name[t] != 0; t++) {
        if (namelist[i]->d_name[t] == '.') {
          namelist[i]->d_name[t] = 0;
          break;
        }
        if ((namelist[i]->d_name[t] >= 'a') || (namelist[i]->d_name[t] <= 'z')) {
          namelist[i]->d_name[t] -= 0x20;
        }
      }
      if (i < 50) ptr += sprintf(ptr, "%9s ", namelist[i]->d_name);
      free(namelist[i]);
    }
    free(namelist);
    *ptr = '$';
    goto DONE;
  }

  if (cmd[0] == 'n') {
    unsigned char imghdr[65536];
    int fsize, fcount;
    FILE *fd;
    int i;
    /* zero out imghdr to avoid leaving there any kind of garbage data */
    memset(imghdr, 0, sizeof(imghdr));
    /* compute the header */
    fsize = floppygen(imghdr, atoi(cmd + 1));
    if (fsize < 1) {
      char *ptr = (char *)(frame->data);
      int sz;
      sz = sprintf(ptr, "ERROR: invalid floppy size. Valid sizes are:\r\n");
      for (i = 0; FDPARMS[i].md != 0; i++) {
        if (sz + strlen(FDPARMS[i].description) + 12 > 512) break;
        sz += sprintf(ptr + sz, "%5d: %s\r\n", FDPARMS[i].totsectors / 2, FDPARMS[i].description);
      }
      ptr[sz] = '$'; /* append the DOS string terminator */
      goto DONE;
    }
    if (validatediskname(arg) != 0) {
      sprintf((char *)(frame->data), "ERROR: specified disk name is invalid$");
      goto DONE;
    }
    disk2fullpath(fullname, sizeof(fullname), storagedir, arg);
    if (fileexists(fullname) != 0) {
      sprintf((char *)(frame->data), "ERROR: a disk with this name already exists$");
      goto DONE;
    }
    fd = fopen(fullname, "wb");
    if (fd == NULL) {
      sprintf((char *)(frame->data), "ERROR: failed to initiate new disk (%s)$", strerror(errno));
      goto DONE;
    }
    /* apply boot sector */
    fcount = (int)fwrite(imghdr, 1, 65536, fd);
    if (fcount != 65536) fprintf(stderr, "WTF fwrite() returned %d\n", fcount);
    /* pad img with zeroes */
    ftruncate(fileno(fd), fsize);
    fclose(fd);
    sprintf((char *)(frame->data), "Disk %s created (%d KiB)$", arg, fsize / 1024);
    goto DONE;
  }

  if (cmd[0] == 'r') {
    /* validate src and dst disk names */
    if ((validatediskname(arg) != 0) || (validatediskname(arg2) != 0)) {
      sprintf((char *)(frame->data), "ERROR: invalid disk name$");
      goto DONE;
    }
    /* compute full paths to img files */
    disk2fullpath(fullname, sizeof(fullname), storagedir, arg);
    disk2fullpath(fullname2, sizeof(fullname2), storagedir, arg2);
    /* make sure src exists */
    if (fileexists(fullname) == 0) {
      sprintf((char *)(frame->data), "ERROR: %s disk does not exist$", arg);
      goto DONE;
    }
    /* make sure dst does not exists yet */
    if (fileexists(fullname2) != 0) {
      sprintf((char *)(frame->data), "ERROR: %s disk already exists$", arg2);
      goto DONE;
    }
    /* make sure src is not in use */
    sce = findcliententrybylock(clist, arg);
    if (sce != NULL) {
      sprintf((char *)(frame->data), "ERROR: the %s disk is currently used by %s$", arg, printmac(sce->mac));
      goto DONE;
    }
    /* do it */
    if (rename(fullname, fullname2) != 0) {
      sprintf((char *)(frame->data), "ERROR: %s$", strerror(errno));
      goto DONE;
    }
    sprintf((char *)(frame->data), "Disk %s renamed to %s$", arg, arg2);
    goto DONE;
  }

  sprintf((char *)(frame->data), "invalid command$");

  DONE:

  /* set answer to current flopid */
  memcpy(&(frame->ax), ce->curflopid, 8);

  return(0);
}


static int raw_sock(const int protocol, const char *const interface, void *const hwaddr) {
  struct ifreq iface;
  struct sockaddr_ll addr;
  int socketfd, result;
  int ifindex;

  if ((interface == NULL) || (*interface == 0)) {
    errno = EINVAL;
    return(-1);
  }

  socketfd = socket(AF_PACKET, SOCK_RAW, htons(protocol));
  if (socketfd == -1) return(-1);

  do {
    memset(&iface, 0, sizeof iface);
    strncpy(iface.ifr_name, interface, sizeof iface.ifr_name - 1);
    result = ioctl(socketfd, SIOCGIFINDEX, &iface);
    if (result == -1) break;
    ifindex = iface.ifr_ifindex;

    memset(&iface, 0, sizeof(iface));
    strncpy(iface.ifr_name, interface, sizeof iface.ifr_name - 1);
    result = ioctl(socketfd, SIOCGIFFLAGS, &iface);
    if (result == -1) break;
    iface.ifr_flags |= IFF_PROMISC;
    result = ioctl(socketfd, SIOCSIFFLAGS, &iface);
    if (result == -1) break;

    memset(&iface, 0, sizeof iface);
    strncpy(iface.ifr_name, interface, sizeof iface.ifr_name - 1);
    result = ioctl(socketfd, SIOCGIFHWADDR, &iface);
    if (result == -1) break;

    memset(&addr, 0, sizeof addr);
    addr.sll_family = AF_PACKET;
    addr.sll_protocol = htons(protocol);
    addr.sll_ifindex = ifindex;
    addr.sll_hatype = 0;
    addr.sll_pkttype = PACKET_HOST | PACKET_BROADCAST;
    addr.sll_halen = ETH_ALEN; /* Assume ethernet! */
    memcpy(&addr.sll_addr, &iface.ifr_hwaddr.sa_data, addr.sll_halen);
    if (hwaddr != NULL) memcpy(hwaddr, &iface.ifr_hwaddr.sa_data, ETH_ALEN);

    if (bind(socketfd, (struct sockaddr *)&addr, sizeof addr)) break;

    errno = 0;
    return(socketfd);
  } while (0);

  {
    const int saved_errno = errno;
    close(socketfd);
    errno = saved_errno;
    return(-1);
  }
}


/* used for debug output of frames on screen */
#if DEBUG > 0
static void dumpframe(void *ptr, int len) {
  int i, b;
  int lines;
  const int LINEWIDTH=16;
  unsigned char *frame = ptr;
  struct FRAME *fields = ptr;
  char flopid[16];

  /* FIELDS */
  printf(" * ax=0x%04X bx=0x%04X cx=0x%04X dx=0x%04X\n", le16toh(fields->ax), le16toh(fields->bx), le16toh(fields->cx), le16toh(fields->dx));
  memset(flopid, 0, sizeof(flopid));
  memcpy(flopid, fields->flopid, 8);
  printf(" * flopid=%s reqid=%u sectnum=%u csum=0x%04X\n", flopid, fields->reqid, fields->sectnum, le16toh(fields->csum));

  /* HEX DUMP NOW */
  lines = (len + LINEWIDTH - 1) / LINEWIDTH; /* compute the number of lines */
  /* display line by line */
  for (i = 0; i < lines; i++) {
    /* read the line and output hex data */
    for (b = 0; b < LINEWIDTH; b++) {
      int offset = (i * LINEWIDTH) + b;
      if (b == LINEWIDTH / 2) printf(" ");
      if (offset < len) {
        printf(" %02X", frame[offset]);
      } else {
        printf("   ");
      }
    }
    printf(" | "); /* delimiter between hex and ascii */
    /* now output ascii data */
    for (b = 0; b < LINEWIDTH; b++) {
      int offset = (i * LINEWIDTH) + b;
      if (b == LINEWIDTH / 2) printf(" ");
      if (offset >= len) {
        printf(" ");
        continue;
      }
      if ((frame[offset] >= ' ') && (frame[offset] <= '~')) {
        printf("%c", frame[offset]);
      } else {
        printf(".");
      }
    }
    /* newline and loop */
    printf("\n");
  }
}
#endif

/* compute the eflop csum of frame, result is always little-endian */
static unsigned short cksum(struct FRAME *frame) {
  unsigned short res = 0;
  uint16_t *ptr = (void *)&(frame->protover);
  int l = 10 + 256; /* how many words to process */
  while (l--) {
    res = (unsigned short)(res >> 15) | (unsigned short)(res << 1); /* rol 1 */
    res ^= le16toh(*ptr);
    ptr++;
  }
  return(htole16(res));
}

static void help(void) {
  printf("ethflopd version " PVER " | Copyright (C) 2019 Mateusz Viste\n"
         "http://ethflop.sourceforge.net\n"
         "\n"
         "usage: ethflopd [options] interface storagedir\n"
         "\n"
         "Options:\n"
         "  -f        Keep in foreground (do not daemonize)\n"
         "  -h        Display this information\n"
  );
}

/* daemonize the process, return 0 on success, non-zero otherwise */
static int daemonize(void) {
  pid_t mypid;

  /* I don't want to get notified about SIGHUP */
  signal(SIGHUP, SIG_IGN);

  /* fork off */
  mypid = fork();
  if (mypid == 0) { /* I'm the child, do nothing */
    /* nothing to do - just continue */
  } else if (mypid > 0) { /* I'm the parent - quit now */
    exit(0);
  } else {  /* error condition */
    return(-2);
  }
  return(0);
}


int main(int argc, char **argv) {
  int datasock, ctrlsock;
  unsigned char mymac[6];
  struct FRAME frame;
  char *intname;
  char *storagedir;
  int opt;
  ssize_t len;
  struct cliententry *clist = NULL, *ce;
  int daemon = 1; /* daemonize self by default */
  struct timespec tp1, tp2; /* used for calculating response time */
  #define LOCKFILE "/var/run/ethflopd.run"
  #define LOCKME lockme(LOCKFILE)
  #define UNLOCKME unlockme(LOCKFILE)

  while ((opt = getopt(argc, argv, "fh")) != -1) {
    switch (opt) {
      case 'f': /* -f: no daemon */
        daemon = 0;
        break;
      case 'h': /* -h: help */
        help();
        return(0);
      case '?': /* error */
        help();
        return(1);
    }
  }
  /* I expect exactly two positional arguments */
  if ((argc - optind) != 2) {
    help();
    return(1);
  }
  intname = argv[optind++];
  storagedir = argv[optind++];

  /* acquire the lock file (fail if already exists - likely ethflopd runs already) */
  if (LOCKME != 0) {
    fprintf(stderr, "Error: failed to acquire a lock. Are you running as root? If so - then perhaps ethflopd is running already? If not, and you're really sure of that, then delete the lock file at '" LOCKFILE "'.\n");
    return(1);
  }

  datasock = raw_sock(0xEFDD, intname, mymac);
  if (datasock == -1) {
    fprintf(stderr, "Error: failed to open socket (%s)\n"
                    "\n"
                    "Usually ethflopd requires to be launched as root for\n"
                    "handling raw (ethernet) sockets. Are you root?\n", strerror(errno));
    UNLOCKME;
    return(1);
  }
  ctrlsock = raw_sock(0xEFDC, intname, mymac);
  if (ctrlsock == -1) {
    fprintf(stderr, "Error: failed to open socket (%s)\n"
                    "\n"
                    "Usually ethflopd requires to be launched as root for\n"
                    "handling raw (ethernet) sockets. Are you root?\n", strerror(errno));
    UNLOCKME;
    return(1);
  }

  /* setup signals catcher */
  signal(SIGTERM, sigcatcher);
  signal(SIGQUIT, sigcatcher);
  signal(SIGINT, sigcatcher);

  printf("Listening on '%s' [%s] ; storage dir=%s\n", intname, printmac(mymac), storagedir);

  if (daemon != 0) {
    if (daemonize() != 0) {
      fprintf(stderr, "Error: failed to daemonize!\n");
      UNLOCKME;
      return(1);
    }
  }

  /* main loop */
  while (terminationflag == 0) {
    struct timeval stimeout = {10, 0}; /* set timeout to 10s */
    fd_set fdset;
    int highestfd;
    highestfd = datasock;
    if (ctrlsock > highestfd) highestfd = ctrlsock;
    /* prepare the set of descriptors to be monitored later through select() */
    FD_ZERO(&fdset);
    FD_SET(datasock, &fdset);
    FD_SET(ctrlsock, &fdset);
    /* wait for something to happen on my socket */
    select(highestfd + 1, &fdset, NULL, NULL, &stimeout);
    clock_gettime(CLOCK_MONOTONIC, &tp1); /* get cur time for later calculation */
    if (recv(datasock, &frame, sizeof(frame), MSG_DONTWAIT) != sizeof(frame)) {
      if (recv(ctrlsock, &frame, sizeof(frame), MSG_DONTWAIT) != sizeof(frame)) continue; /* restart if size not what I expect or negative */
    }
    /* validate this is for me (or broadcast) */
    if ((memcmp(mymac, frame.dmac, 6) != 0) && (memcmp("\xff\xff\xff\xff\xff\xff", frame.dmac, 6) != 0)) continue; /* skip anything that is not for me */
    /* is this valid ethertype ?*/
    if ((frame.etype != htons(0xEFDD)) && (frame.etype != htons(0xEFDC))) {
      fprintf(stderr, "Error: Received invalid ethertype frame (0x%u)\n", ntohs(frame.etype));
      continue;
    }
    /* */
  #if DEBUG > 0
    DBG("Received frame from %s\n", printmac(frame.smac));
    dumpframe(&frame, sizeof(frame));
  #endif
   #if SIMLOSS_INP > 0
    /* simulated frame LOSS (input) */
    if ((rand() % 100) < SIMLOSS_INP) {
      fprintf(stderr, "INPUT LOSS! (reqid %d)\n", frame.reqid);
      continue;
    }
   #endif
    /* validate CKSUM */
    {
      unsigned short cksum_mine;
      cksum_mine = cksum(&frame);
      if (cksum_mine != frame.csum) {
        fprintf(stderr, "CHECKSUM MISMATCH! Computed: 0x%02Xh Received: 0x%02Xh\n", cksum_mine, frame.csum);
        continue;
      }
    }
    /* convert ax/bx/cx/dx to host order */
    frame.ax = le16toh(frame.ax);
    frame.bx = le16toh(frame.bx);
    frame.cx = le16toh(frame.cx);
    frame.dx = le16toh(frame.dx);
    /* find client entry */
    ce = findorcreateclient(&clist, frame.smac);
    if (ce == NULL) {
      fprintf(stderr, "ERROR: OUT OF MEMORY!\n");
      continue;
    }
    /* process frame */
    if (frame.etype == htons(0xEFDD)) {
      if (process_data(&frame, mymac, ce) != 0) continue;
    } else if (frame.etype == htons(0xEFDC)) {
      if (process_ctrl(&frame, mymac, storagedir, ce, clist) != 0) continue;
    } else {
      fprintf(stderr, "Error: unsupported ethertype from %s (0x%02x)\n", printmac(frame.smac), ntohs(frame.etype));
      continue;
    }
    /* */
   #if SIMLOSS_OUT > 0
    /* simulated frame LOSS (output) */
    if ((rand() % 100) < SIMLOSS_OUT) {
      fprintf(stderr, "OUTPUT LOSS! (reqid %d)\n", frame.reqid);
      continue;
    }
   #endif
    DBG("---------------------------------\n");
    /* convert new register values to little-endian */
    frame.ax = htole16(frame.ax);
    frame.bx = htole16(frame.bx);
    frame.cx = htole16(frame.cx);
    frame.dx = htole16(frame.dx);
    /* fill in checksum into the answer */
    frame.csum = cksum(&frame);
  #if DEBUG > 0
      DBG("Sending back an answer of %lu bytes\n", sizeof(frame));
      dumpframe(&frame, sizeof(frame));
  #endif
    /* wait 0.5 ms - just to make sure that ethflop had time to prepare itself - due to ethflop using a single buffer for send/recv operations it needs a tiny bit of time to switch from 'sending' to 'receiving'. 0.5 ms should be enough even for the slowest PC (4MHz) and the crappiest packet driver (that would need 2000 cycles to return from sending a packet) */
    {
      struct timespec nanot;
      nanot.tv_sec = 0;
      nanot.tv_nsec = 500 * 1000; /* 1000 ns is 1 us. 1000 us is 1 ms */
      nanosleep(&nanot, NULL);
    }
    len = send(datasock, &frame, sizeof(frame), 0);
    clock_gettime(CLOCK_MONOTONIC, &tp2); /* get cur time */
    if (len < 0) {
      fprintf(stderr, "ERROR: send() returned %ld (%s)\n", len, strerror(errno));
    } else if (len != sizeof(frame)) {
      fprintf(stderr, "ERROR: send() sent less than expected (%ld != %lu)\n", len, sizeof(frame));
    }
    { /* compute answer time */
      long msec;
      msec = (tp2.tv_sec - tp1.tv_sec) * 1000;
      tp1.tv_nsec /= 1000000l; /* convert ns to ms */
      tp2.tv_nsec /= 1000000l; /* convert ns to ms */
      if (tp2.tv_nsec < tp1.tv_nsec) {
        msec -= 1000;
        tp2.tv_nsec += 1000;
      }
      msec += (tp2.tv_nsec - tp1.tv_nsec);
      if (msec > 10) fprintf(stderr, "WARNING: query took a long time to process (%ld ms)\n", msec);
    }
    DBG("---------------------------------\n");
  }

  /* remove lock file and quit */
  UNLOCKME;
  return(0);
}
