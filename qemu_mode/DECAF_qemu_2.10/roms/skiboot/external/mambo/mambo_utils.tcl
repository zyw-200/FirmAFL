
#
# behave like gdb
#
proc p { reg { t 0 } { c 0 } } {
    switch -regexp $reg {
        ^r[0-9]+$ {
            regexp "r(\[0-9\]*)" $reg dummy num
            set val [mysim cpu $c thread $t display gpr $num]
            puts "$val"
        }
        ^f[0-9]+$ {
            regexp "f(\[0-9\]*)" $reg dummy num
            set val [mysim cpu $c thread $t display fpr $num]
            puts "$val"
        }
        ^v[0-9]+$ {
            regexp "v(\[0-9\]*)" $reg dummy num
            set val [mysim cpu $c thread $t display vmxr $num]
            puts "$val"
        }
        default {
            set val [mysim cpu $c thread $t display spr $reg]
            puts "$val"
        }
    }
}

#
# behave like gdb
#
proc sr { reg val {t 0}} {
    switch -regexp $reg {
        ^r[0-9]+$ {
            regexp "r(\[0-9\]*)" $reg dummy num
            mysim cpu 0:$t set gpr $num $val
        }
        ^f[0-9]+$ {
            regexp "f(\[0-9\]*)" $reg dummy num
            mysim cpu 0:$t set fpr $num $val
        }
        ^v[0-9]+$ {
            regexp "v(\[0-9\]*)" $reg dummy num
            mysim cpu 0:$t set vmxr $num $val
        }
        default {
            mysim cpu 0:$t set spr $reg $val
        }
    }
    p $reg $t
}

proc b { addr } {
    mysim trigger set pc $addr "just_stop"
    set at [i $addr]
    puts "breakpoint set at $at"
}

proc wr { start stop } {
    mysim trigger set memory system w $start $stop 0 "just_stop"
}

proc c { } {
    mysim go
}

proc i { pc { t 0 } { c 0 } } {
    set pc_laddr [mysim cpu $c util itranslate $pc]
    set inst [mysim cpu $c memory display $pc_laddr 4]
    set disasm [mysim cpu $c util ppc_disasm $inst $pc]
    return "\[$c:$t\]: $pc ($pc_laddr) Enc:$inst : $disasm"
}

proc ipc { {t 0} {c 0}} {
    set pc [mysim cpu $c thread $t display spr pc]
    i $pc $t $c
}

proc ipca { } {
    set cpus [myconf query cpus]
    set threads [myconf query processor/number_of_threads]

    for { set i 0 } { $i < $cpus } { incr i 1 } {
        for { set j 0 } { $j < $threads } { incr j 1 } {
            puts [ipc $j $i]
        }
    }
}

proc pa { spr } {
    set cpus [myconf query cpus]
    set threads [myconf query processor/number_of_threads]

    for { set i 0 } { $i < $cpus } { incr i 1 } {
        for { set j 0 } { $j < $threads } { incr j 1 } {
            set val [mysim cpu $i thread $j display spr $spr]
            puts "CPU: $i THREAD: $j SPR $spr = $val" 
        }
    }
}

proc s { } {
    mysim step 1
    ipca
}

proc z { count } {
    while { $count > 0 } {
        s
        incr count -1
    }
}

proc sample_pc { sample count } {
    while { $count > 0 } {
        mysim cycle $sample
        ipc
        incr count -1
    }
}

proc e2p { ea } {
    set pa [ mysim util dtranslate $ea ]
    puts "$pa"
}

proc x {  pa { size 8 } } {
    set val [ mysim memory display $pa $size ]
    puts "$pa : $val"
}

proc it { ea } {
    mysim util itranslate $ea
}
proc dt { ea } {
    mysim util dtranslate $ea
}

proc ex {  ea { size 8 } } {
    set pa [ mysim util dtranslate $ea ]
    set val [ mysim memory display $pa $size ]
    puts "$pa : $val"
}

proc hexdump { location count }    {
    set addr  [expr $location & 0xfffffffffffffff0]
    set top [expr $addr + ($count * 15)]
    for { set i $addr } { $i < $top } { incr i 16 } {
        set val [expr $i + (4 * 0)]
        set val0 [format "%08x" [mysim memory display $val 4]]
        set val [expr $i + (4 * 1)]
        set val1 [format "%08x" [mysim memory display $val 4]]
        set val [expr $i + (4 * 2)]
        set val2 [format "%08x" [mysim memory display $val 4]]
        set val [expr $i + (4 * 3)]
        set val3 [format "%08x" [mysim memory display $val 4]]
        set ascii "(none)"
        set loc [format "0x%016x" $i]
        puts "$loc: $val0 $val1 $val2 $val3 $ascii"
    }
}

proc slbv {} {
    puts [mysim cpu 0 display slb valid]
}

proc regs { { t 0 } { c 0 } } {
    puts "GPRS:"
    puts [mysim cpu $c thread $t display gprs]
}

proc tlbv { { c 0 } } {
    puts "$c:TLB: ----------------------"
    puts [mysim cpu $c display tlb valid]
}

proc just_stop { args } {
    simstop
    ipca
}

proc st { count } {
    set sp [mysim cpu 0 display gpr 1]
    puts "SP: $sp"
    ipc
    set lr [mysim cpu 0 display spr lr]
    i $lr
    while { $count > 0 } {
        set sp [mysim util itranslate $sp]
        set lr [mysim memory display [expr $sp++16] 8]
        i $lr
        set sp [mysim memory display $sp 8]

        incr count -1
    }
}

proc mywatch { } {
    while { [mysim memory display 0x700 8] != 0 } {
        mysim cycle 1
    }
    puts "condition occurred "
    ipc
}

#
# force gdb to attach
#
proc gdb { {t 0} } {
    mysim set fast off
    mysim debugger wait $t
}

proc egdb { {t 0} } {
    set srr0 [mysim cpu 0 display spr srr0]
    set srr1 [mysim cpu 0 display spr srr1]
    mysim cpu 0 set spr pc $srr0
    mysim cpu 0 set spr msr $srr1
    gdb $t
}

proc mem_display_64_le { addr } {
    set data 0
    for {set i 0} {$i < 8} {incr i} {
	set data [ expr $data << 8 ]
	set l [ mysim memory display [ expr $addr+7-$i ] 1 ]
	set data [ expr $data | $l ]
    }
    return [format 0x%X $data]
}

proc mem_display_64 { addr le } {
    if { $le } {
	return [ mem_display_64_le $addr ]
    }
    # mysim memory display is big endian
    return [ mysim memory display $addr 8 ]
}

proc bt { {sp 0} } {
    set t 0
    if { $sp < 16 } {
        set t $sp
        set sp 0
    }
    set lr [mysim cpu 0:$t display spr pc]
    puts "pc:\t\t\t\t$lr"
    if { $sp == 0 } {
        set sp [mysim cpu 0:$t display gpr 1]
    }
    set lr [mysim cpu 0:$t display spr lr]
    puts "lr:\t\t\t\t$lr"

    set msr [mysim cpu 0:$t display spr msr]
    set le [ expr $msr & 1 ]

    # Limit to 200 in case of an infinite loop
    for {set i 0} {$i < 200} {incr i} {
        set pa [ mysim util dtranslate $sp ]
        set bc [ mem_display_64 $pa $le ]
        set lr [ mem_display_64 [ expr $pa + 16 ] $le ]
        puts "stack:$pa \t$lr"
        if { $bc == 0 } { break }
        set sp $bc
    }
    puts ""
}

proc ton { } {mysim mode turbo }
proc toff { } {mysim mode simple }

proc don { opt } {
    simdebug set $opt 1
}

proc doff { opt } {
    simdebug set $opt 0
}

