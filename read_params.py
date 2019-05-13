import re
def readParamFile(fileName):
    f=file(fileName,'r')
    lngstr=f.read()
    f.close()
    lines = lngstr.split('\n')

    params = {}
    nextkey=''
    morehex=''
    for i in range(len(lines)):
        output = re.findall('^\s*([^:]*?):\s*$', lines[i])
        if len(output) == 1:
            if nextkey != '' and morehex != '':
                params[nextkey] = int(morehex.replace(':',''), 16)
            nextkey = output[0]
            morehex = ''
        else:
            output = re.findall('^\s*(.*?)\s*$', lines[i])
            if len(output) == 1:
                morehex += output[0]
    if nextkey != '' and morehex != '':
        params[nextkey] = int(morehex.replace(':',''), 16)
    print params