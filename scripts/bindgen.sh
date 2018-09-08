#!/bin/sh
set -x
for d in /usr/bin /usr/local/bin /opt/local/bin ~/bin ~/perl/bin
do
    for p in $d/perl $d/perl5.[0123][02468].* \
             $d/cperl $d/cperl5.2[2468].*
    do
        if [ -e "$p" ]; then
            core=`$p -MConfig -e'print qq($Config{archlib}/CORE)'`
            name=`basename $p`
            if [ -d "$core" ]; then
               # multi, thread or not
               cat $core/{EXTERN,perl,XSUB}.h > src/versions/$name.h
               bindgen src/versions/$name.h \
                       -o src/versions/$name.rs \
                       --impl-debug \
                       --rust-target 1.25 \
                       --ignore-functions \
                       --no-rustfmt-bindings \
                       --no-doc-comments \
                       --whitelist-type PerlInterpreter \
                       --whitelist-type PL_curinterp \
                       --whitelist-type PL_curcop \
                       --whitelist-type PL_curstack \
                       --whitelist-type STRUCT_SV \
                       --whitelist-type sv \
                       --whitelist-type av \
                       --whitelist-type cv \
                       --whitelist-type gv \
                       -- -I$core
               rustfmt --force --write-mode overwrite \
                       src/versions/$name.rs
            fi
        fi
    done
done
rm src/version/c?perl5*@* 2>/dev/null

#echo "#![allow(non_upper_case_globals)]" > $OUT
#echo "#![allow(non_camel_case_types)]" >> $OUT
#echo "#![allow(non_snake_case)]" >> $OUT
#cat /tmp/bindings.rs >> $OUT
#
## fix up generated bindings so that they compile/work on windows
#perl -pi -e "s/::std::os::raw::c_ulong;/usize;/g" $OUT
#perl -pi -e "s/63u8\) as u64/63u8\) as usize/g" $OUT
#perl -pi -e "s/let val: u64 =/let val: usize =/g" $OUT
#perl -pi -e "s/let num_entries: u64 =/let num_entries: usize =/g" $OUT
