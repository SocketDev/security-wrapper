import subprocess
import pickle

def insecure_eval(user_input):
    # B307: eval used
    return eval(user_input)

def insecure_subprocess(cmd):
    # B602: subprocess call with shell=True
    subprocess.call(cmd, shell=True)

def insecure_pickle(data):
    # B301: pickle load
    return pickle.loads(data)

def hardcoded_password():
    # B105: hardcoded password string
    password = "supersecret123"
    return password

def insecure_tempfile():
    # B108: insecure use of temp file
    import tempfile
    f = tempfile.NamedTemporaryFile(delete=False)
    f.write(b"test")
    f.close()