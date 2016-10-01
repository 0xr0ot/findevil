# findevil
Volatility plugin to find known bad in processes or memory

## Config
Copy findevilinfo.py, findevilmem.py, and findevilproc.py to volatility/plugins/ directory or specify the directory using --plugins command line argument.

Insert your VirusTotal API Key and Yara rules folder into findevilinfo.py

You can find your VirusTotal API Key here:
https://www.virustotal.com/en/user/username/apikey/

```
VT_API_KEY = "INSERT_VT_API_KEY_HERE"
YARA_RULES_DIR = "INSERT_YARA_RULES_DIR_HERE"
```

## Usage

### findevilproc
```
python vol.py -f sample001.bin --profile=WinXPSP2x86 findevilproc                     
Volatility Foundation Volatility Framework 2.5                                                                                                                      
Creating Dump Dir /Users/tyh/findevil/dump_tmp                                                                                                                 
Name                 Result                    Hash                                                             Verdict    Signed   Entropy      Yara               
-------------------- ------------------------- ---------------------------------------------------------------- ---------- -------- ------------ ----               
smss.exe             OK: executable.356.exe    ea685dbb85c017483eca210511098e1ea7c3a0e7c35aa0eb37065b0a209924f1 Not in VT  Unsigned 5.723...5913 [test.yar]  
csrss.exe            OK: executable.604.exe    f53cdb9e5aa4ab9f1d88842cfe0cf39d9587800fa320cc0ce14f8234e540bfd8 Not in VT  Unsigned 3.927...0292 [test.yar]  
winlogon.exe         OK: executable.628.exe    682cc1f99dbb82959d856fb520dcdb530ebd85541561f7b3fedf430d16529ef3 1 / 56     Unsigned 3.059...7028 [test.yar]  
services.exe         OK: executable.680.exe    29232def4dd960349b3ad4f09d89a423d38c7a48a1826570935b6d6ff0dbe53d Not in VT  Unsigned 6.009...4422 [test.yar]  
lsass.exe            OK: executable.692.exe    f49df40d8512c973de8a5b33b0bda4e98f3b63bc0a455576a454120033596a54 Not in VT  Unsigned 0.318...9337 [test.yar]  
svchost.exe          OK: executable.852.exe    ac7d90717499feda0e127dd98f0fc5fd2093e0ca2197b6c829c652beb8ccae78 0 / 54     Unsigned 5.757...1102 [test.yar]  
svchost.exe          OK: executable.940.exe    f5099da5bee3ab3167fffca2cafd528f2812fcea49318511629b0dc66a1c54c5 0 / 55     Unsigned 5.754...4895 [test.yar]  
svchost.exe          OK: executable.1024.exe   ad1a6c59c676257e8b138907679c3d6d9feba50f7d398487b2a38d43d51d4e9b 1 / 57     Unsigned 5.791...5202 [test.yar]  
svchost.exe          OK: executable.1068.exe   569ac9bb1f0d772c26653aba143a573947d9f151cf7d107831f18ab4ca3324f6 0 / 57     Unsigned 5.789...0276 [test.yar]  
svchost.exe          OK: executable.1116.exe   aad37b67b847c07e44cf03388a48b2fdefa9d287f3cb3eca070935dee1d7351c 0 / 55     Unsigned 5.787...6153 [test.yar]  
spoolsv.exe          OK: executable.1348.exe   d9af87f84fbdd27e8ee5e273e40a25b41de3bb058d563bffbed5c2c94caffe90 Not in VT  Unsigned 3.887...3312 [test.yar]  
alg.exe              OK: executable.1888.exe   3db3d30aab1a70e39ba4d1ae692908271c30e8e82da753f266f246b596412fc5 2 / 56     Unsigned 5.843...7447 [test.yar]  
explorer.exe         OK: executable.284.exe    bf4c39e75f3cac4c8b8cced18c34b9ed6eac2cdaed85f112c96a3e3f8d4bb318 4 / 57     Unsigned 2.278...4206 [test.yar]  
msmsgs.exe           OK: executable.548.exe    cb20dc96d0fe1ff46c1b3a04920674103c085dca958ba4702f553874d6bbbdb7 1 / 55     Unsigned 1.417...2518 [test.yar]  
ctfmon.exe           OK: executable.556.exe    9fbdb0c992c9100807d1326e7139b919a8d09e7e574fe49beedb202063040bfe 2 / 55     Unsigned 6.141...1069 [test.yar]  
wuauclt.exe          OK: executable.1628.exe   f11d7931ae893ac103377cad7ea283cce2d405aeae18745e72d1a206177266b7 0 / 55     Unsigned 4.663...0669 [test.yar]  
msimn.exe            OK: executable.1984.exe   28b07ac81372bde4e4240b4fbc34b0620a4274ec721358f9c32a794af292581d 4 / 56     Unsigned 1.692...6666 [test.yar]  
wc.exe               OK: executable.364.exe    4615db3a06a2fbb2f2eeeab0cba1ff4305800088a424b110c409798c51a501ad 50 / 57    Unsigned 5.8195136826 [test.yar]  
cmd.exe              OK: executable.1796.exe   7bb84ba2090e88cc626bf7d4f7a8114743e341a5dd278011310d3a528f0a2b14 0 / 57     Unsigned 2.834...2945 [test.yar]  
mdd.exe              OK: executable.244.exe    74cd98d1f4d95ae5104e097b7a5a895d2e8e8067a143208dd6003e65d2dcc56e 1 / 54     Signed   6.175...3032 [test.yar]
```


### findevilmem

```
python vol.py -f sample001.bin --profile=WinXPSP2x86 findevilmem
Volatility Foundation Volatility Framework 2.5
Creating Dump Dir /Users/tyh/findevil/dump_tmp
Writing System [     4] to 4.dmp
Carving dll at 0x25000
Carving exe at 0x10d000
Carving exe at 0x170000
Carving exe at 0x38d000
Carving exe at 0x3b1000
Carving dll at 0x5c8000
Carving dll at 0x18519bd
Carving exe at 0x18528a1
Carving sys at 0x2b76000
Carving exe at 0x2d59000
Carving exe at 0x2efc000
Carving exe at 0x3c93000
Carving dll at 0x3cb7000
Carving exe at 0x3cfa000
Carving exe at 0x3d7d000
Carving exe at 0x3ded000
Carving exe at 0x3e6d000
Carving dll at 0x3e8f000

...

Name                 Hash                                                             Verdict    Signed   Entropy      Yara
-------------------- ---------------------------------------------------------------- ---------- -------- ------------ ----
1024.dmp             5744ccdf655285961ee3118883f404c2c76f9bdad13d5eb58357186953d33d9b 1 / 55     Error    4.942...8067 [test.yar]
1024.dmp_1.dll       269a619878bdbea98513af1b4aac92b2ee7a112d4291194ff045defcc75dacfd Not in VT  Unsigned 1.988...1049 [test.yar]
1024.dmp_10.dll      ba28cf6f81efa76a09daf828b6a1f1468e9e156e0acb09faa6f4e6c197b1910a Not in VT  Unsigned 5.752...2504 [test.yar]
1024.dmp_100.dll     cc965aea53f59c54f696897b8bd2392ca115ac2ccae2b968872f3c7eb484f200 Not in VT  Unsigned 5.531...2653 [test.yar]
1024.dmp_101.dll     d72869bda905d447e78362a83d462562732b45294bbb715f9beed9519ca74314 Not in VT  Unsigned 5.438...5321 [test.yar]
1024.dmp_102.dll     659eba4c0b58829e5676d53782a0e0b0be4adf355e0482cdf7928bb6f6069ded Not in VT  Unsigned 4.231...5623 [test.yar]
1024.dmp_103.dll     d997ff56fa3bc4795d2a4cf73d467dba310ba83603988731512119efac8903ef Not in VT  Unsigned 4.7349923195 [test.yar]
1024.dmp_104.dll     e6a329721ef150e143ad49e79e3a28c2aadfe1e1968b8f253ffb219e0bd846c8 Not in VT  Unsigned 5.631...2887 [test.yar]
1024.dmp_105.dll     95d26ea5a77178b8f78d992fbacaa5d7af6433a21d564e4df1ed8b62fa903c76 Not in VT  Unsigned 5.767...5828 [test.yar]
1024.dmp_106.dll     bdc158f1574871a505ac3ce3ba1f2e9cead5d8d56cb1b123aa723006047d1c39 Not in VT  Unsigned 5.425...6229 [test.yar]
1024.dmp_107.dll     06dc56156762c841ed198ae17280f224c10e0dd76075847be5a4b98ab4fe7242 Not in VT  Unsigned 5.480...6917 [test.yar]
1024.dmp_108.dll     b0b06fd63cf9e13180ff09aa9ddc339a75459079818e0155f5edb1057913d101 Not in VT  Unsigned 5.350...3928 [test.yar]

...

1024.dmp_7.sys       14605e87c5ef7fab67a7626e64bf1020d79730298eec36b8791d40af709b0759 52 / 57    Unsigned 3.886...1352 [test.yar]
1024.dmp_70.dll      abea94e7304862f5e657862713a8ab7ae9e044a5aaae499df396d6f91af33843 Not in VT  Unsigned 4.325...0973 [test.yar]
...
```