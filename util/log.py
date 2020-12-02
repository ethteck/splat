from colorama import init, Fore, Style

init(autoreset=True)

newline = True

def write(*args, status=None, **kwargs):
    global newline

    if not newline:
        print("")
        newline = True

    print(status_to_ansi(status) + str(args[0]), *args[1:], **kwargs)

def dot(status=None):
    global newline

    print(status_to_ansi(status) + ".", end="")
    newline = False

def status_to_ansi(status):
    if status == "ok":
        return Fore.GREEN
    elif status == "error":
        return Fore.RED
    elif status == "skip":
        return Style.DIM
    else:
        return ""
