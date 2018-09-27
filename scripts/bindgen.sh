#!/bin/sh
set -x
test -e src/perl_versions/mod.rs && mv src/perl_versions/mod.rs src/perl_versions/mod.rs~
for d in /usr/bin /usr/local/bin /opt/local/bin ~/bin ~/perl/bin
do
    for p in $d/perl $d/cperl \
             $d/perl5.[0123][02468].0-thr \
             $d/perl5.[0123][02468].0-nt \
             $d/perl5.[0123][02468].0d \
             $d/perl5.[0123][02468].0d-nt \
             $d/cperl $d/cperl5.2[2468].0-thr \
             $d/cperl $d/cperl5.2[2468].0-nt \
             $d/cperl $d/cperl5.2[2468].0d \
             $d/cperl $d/cperl5.2[2468].0d-nt;
    do
        if [ -e "$p" ]; then
            core=`$p -MConfig -e'print qq($Config{archlib}/CORE)'`
            name=`basename $p`
            name=`echo $name|perl -pe 's/-/_/g; s/\.([0-9])/_\1/g'`
            # TODO: only take the first major, skip any @
            if [ -d "$core" ]; then
               # multi, threads or not
               cat $core/{EXTERN,perl,XSUB}.h > src/perl_versions/$name.h
               bindgen src/perl_versions/$name.h \
                       -o src/perl_versions/$name.rs \
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
               if [ -e src/perl_versions/$name.rs ]; then
                   perl -pi -e 'print "#![allow(non_upper_case_globals)]\n#![allow(non_camel_case_types)]\n#![allow(non_snake_case)]\n" if $. == 1;' src/perl_versions/$name.rs
                   perl -pi -e 's/^\Q#[derive(Copy, Clone)]; \E\d+\Qusize ] , }\E//' src/perl_versions/$name.rs
                   rustfmt --force --write-mode overwrite src/perl_versions/$name.rs
                   echo "pub mod $name;" >> src/perl_versions/mod.rs
               fi
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
