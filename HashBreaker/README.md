### Purpose
Takes a file with line-separated [username, hashOfUserPassword] (or [username, userSalt, hashOfUserPasswordAndSalt]) entries and discovers the password corresponding to each entry.

The method of password guessing can be Random or Sequential.
* Sequential could be "A", "B", "C", ... "Z", "a", "b", ... "z", "@", "AA", "AB", "AC", ..., "AZ", "Aa", ..., "Az", "A@", "BA", ..., "Bz", "B@", ..., "ZZ", "Z@", ..., "@Z", "@@", ..., "AAA", ...
* Sequential can start at a certain password length (`NUM_CHARS_IN_PW`), increasing in length until the password is found. Note that it will *never* check passwords that have shorter lengths.
* Random could be "ZXY@", "AAAB", "@@zQ", ...
* Further testing on Random needs to verify that increasing lengths of passwords will be tested.

The alphabet of possible characters in the passwords can be easily adjusted by modifying `possibleChars`.
* By default, the program uses uppercase and lowercase English letters, combined with digits and "#$%^&*" (ignoring the double quotes themselves).

More specifics/documentation about the requirements of the password file's format can be found in the program itself. The default password files are intentionally messed up a bit to show you that it can tolerate a few different formats. Note that tolerating these extra formats makes the program very slightly slower.

`generateNewHashes()` is for when you don't have an existing password file and you need to create one for testing purposes.

The "HashBreaker_concise.py" file is the exact same as the "HashBreaker.py" file,
EXCEPT that the former file has both fewer debugging capabilities, and the file's remaining debug statements are commented out. There may be slightly fewer intermediate variables in the former file as well.
  
  
## To run
### Requirements
Must already have Python3 for **Windows** installed, which can be acquired at https://www.python.org/downloads/. Pycryptodome may have extra Python version requirements that are not stated here. This has been tested on Microsoft Windows 10 Home.

### Conflicts
If both Python 2 and Python 3 are present on your system, Python 3 must have a higher priority in your system PATH. In worst case where everything else has been double checked, completely remove Python 2 from your system PATH.

Please note that there are packages with similar names to Pycryptodome. They are likely to have issues but the library imports may work with the program's "import Crypto" statements. Do not use the libraries that sound similar or related; use Pycryptodome. An exception MIGHT be Pycryptodomex - I have not fully tested it.

### Execution
* Open Windows File Explorer, navigate to HashBreaker folder (by default, it's in the Downloads folder, but I recommend you move it elsewhere), enter the folder. If you just copied individual files instead of the folder, just go to the folder where ALL the files in this repository are stored, then enter that folder.

* Open Windows Command Prompt (not powershell) by clicking on the address bar at the top (which shows the location of the file), typing `cmd`, then pressing the Enter key on keyboard. The command prompt is now looking at the same files you were looking at in File Explorer.

`py -m venv virtEnv`
* This creates a Python virtual environment, where libraries installed to the virtual environment don't conflict with any other program's libraries (only once the environment is activated).

`virtEnv\Scripts\activate`
*  Note the backslashes instead of forward slashes. Forward slashes don’t work. Do not add any extra slashes.

`pip install pycryptodome`

`py myPythonExecutableFile.py`
