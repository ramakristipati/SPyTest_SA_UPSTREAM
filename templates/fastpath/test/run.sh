#!/bin/bash

cd $(dirname $0)

PYTHON=../../../bin/python3

#export SPYTEST_TEXTFSM_TRACE_PARSER=1
#export SPYTEST_TEXTFSM_PDB_PARSER=1
#export SPYTEST_TEXTFSM_CUSTOM_PARSER=/projects/scid/dev/vendor

#export SPYTEST_TEXTFSM_DUMP_INDENT_JSON=1
export SPYTEST_TEXTFSM_PLATFORM="fastpath"
#export SPYTEST_TEXTFSM_ROOT="fp_templates"
RUN="$PYTHON ../../../spytest/template.py"

$RUN "show port all" fp_show_port_all.txt
$RUN "show interfaces status all" fp_show_interface_status.txt
$RUN "show hosts" fp_show_hosts.txt
$RUN "devsh 'taDebugPortInfo All,PHYSICAL'" fp_taDebugPortInfo_1.txt
$RUN "devsh taDebugSysInfo" fp_taDebugSysInfo_1.txt
