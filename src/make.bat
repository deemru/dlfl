cl /c /Ox /Os /GL /GF /GS- /W4 dlfl.c
rc -r dlfl.rc
link /LTCG dlfl.obj dlfl.res /subsystem:console /MERGE:.rdata=.text