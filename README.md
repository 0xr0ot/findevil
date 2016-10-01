# findevil
Volatility plugin to find known evil

## Config
Insert your VirusTotal API Key and Yara rules folder into findevilinfo.py

```
VT_API_KEY = "INSERT_VT_API_KEY_HERE"
YARA_RULES_DIR = "INSERT_YARA_RULES_DIR_HERE"
```

## Usage

```
python vol.py -f sample001.bin --profile=WinXPSP2x86 findevilproc                     
Volatility Foundation Volatility Framework 2.5                                                                                                                      
Dump Dir Already Exists /Users/thalfpop/findevil/dump_tmp                                                                                                           
Name                 Result                    Verdict    Signed   Entropy      Yara                                                                                
-------------------- ------------------------- ---------- -------- ------------ ----                                                                                
smss.exe             OK: executable.356.exe    Not in VT  Unsigned 5.723...5913 [test.yar]                                                                   
csrss.exe            OK: executable.604.exe    Not in VT  Unsigned 3.927...0292 [test.yar]                                                                   
winlogon.exe         OK: executable.628.exe    1 / 56     Unsigned 3.059...7028 [test.yar]                                                                   
services.exe         OK: executable.680.exe    Not in VT  Unsigned 6.009...4422 [test.yar]                                                                   
lsass.exe            OK: executable.692.exe    Not in VT  Unsigned 0.318...9337 [test.yar]                                                                   
svchost.exe          OK: executable.852.exe    0 / 54     Unsigned 5.757...1102 [test.yar]                                                                   
svchost.exe          OK: executable.940.exe    0 / 55     Unsigned 5.754...4895 [test.yar]                                                                   
svchost.exe          OK: executable.1024.exe   1 / 57     Unsigned 5.791...5202 [test.yar]                                                                   
svchost.exe          OK: executable.1068.exe   0 / 57     Unsigned 5.789...0276 [test.yar]                                                                   
svchost.exe          OK: executable.1116.exe   0 / 55     Unsigned 5.787...6153 [test.yar]                                                                   
spoolsv.exe          OK: executable.1348.exe   Not in VT  Unsigned 3.887...3312 [test.yar]                                                                   
alg.exe              OK: executable.1888.exe   2 / 56     Unsigned 5.843...7447 [test.yar]                                                                   
explorer.exe         OK: executable.284.exe    4 / 57     Unsigned 2.278...4206 [test.yar]                                                                   
msmsgs.exe           OK: executable.548.exe    1 / 55     Unsigned 1.417...2518 [test.yar]                                                                   
ctfmon.exe           OK: executable.556.exe    2 / 55     Unsigned 6.141...1069 [test.yar]                                                                   
wuauclt.exe          OK: executable.1628.exe   0 / 55     Unsigned 4.663...0669 [test.yar]                                                                   
msimn.exe            OK: executable.1984.exe   4 / 56     Unsigned 1.692...6666 [test.yar]                                                                   
wc.exe               OK: executable.364.exe    50 / 57    Unsigned 5.8195136826 [test.yar]                                                                   
cmd.exe              OK: executable.1796.exe   0 / 57     Unsigned 2.834...2945 [test.yar]                                                                   
mdd.exe              OK: executable.244.exe    1 / 54     Signed   6.175...3032 [test.yar]
```