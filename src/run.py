with open("netServ.py") as fp:
    for i, line in enumerate(fp):
        if "\xc3" in line:
            print i, repr(line)