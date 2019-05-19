\ *****************************************************************************
\ * Copyright (c) 2004, 2008 IBM Corporation
\ * All rights reserved.
\ * This program and the accompanying materials
\ * are made available under the terms of the BSD License
\ * which accompanies this distribution, and is available at
\ * http://www.opensource.org/licenses/bsd-license.php
\ *
\ * Contributors:
\ *     IBM Corporation - initial implementation
\ ****************************************************************************/

s" obp-tftp" device-name

VARIABLE huge-tftp-load 1 huge-tftp-load !

: open ( -- okay? ) 
    true
;

: load ( addr -- size )
    s" bootargs" get-chosen 0= IF 0 0 THEN >r >r
    s" bootpath" get-chosen 0= IF 0 0 THEN >r >r

    \ Set bootpath to current device
    my-parent ihandle>phandle node>path encode-string
    s" bootpath" set-chosen

    60000000                        ( addr maxlen )

    \ Allocate 1720 bytes to store the BOOTP-REPLY packet
    6B8 alloc-mem dup >r            ( addr maxlen replybuf )
    huge-tftp-load @  d# 1428       ( addr maxlen replybuf hugetftp blocksize )
    \ Add OBP-TFTP Bootstring argument, e.g. "10.128.0.1,bootrom.bin,10.128.40.1"
    my-args
    net-load dup 0< IF drop 0 THEN

    \ Recover buffer address of BOOTP-REPLY packet
    r>

    r> r> over IF s" bootpath" set-chosen ELSE 2drop THEN
    r> r> over IF s" bootargs" set-chosen ELSE 2drop THEN

    \ Store BOOTP-REPLY packet as property
    dup 6B8 encode-bytes s" bootp-response" s" /chosen" find-node set-property

    \ free buffer
    6B8 free-mem
;

: close ( -- )
;

: ping  ( -- )
    my-args net-ping
;
