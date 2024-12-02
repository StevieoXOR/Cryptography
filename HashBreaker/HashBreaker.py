
from Crypto.Hash import SHA256
from time import perf_counter_ns, time_ns
import string	# For getRandomWord() and getSequentialWordUsingIdx() and getSequentialWordUsingExactLen()
import random	# For getRandomWord()


DEBUG = False
USE_SALT = True			# Should match whether desired password file uses regular ASCII salts.
# ^ Set to False if pw file doesn't use salt or if pw file uses hex salt.
# ^ Determines whether hashVal=hashFunc(pw+salt) or hashVal=hashFunc(pw).
USE_HEX_SALT = False	# Whether to read salt as ASCII or ASCIIbutRepresentedAsHex
# ^ E.g., saltFromFile="6667":  salt="6667" or  b"6667"->fromHexToASCII->"fg"
# ^ Determines whether to interpret salts in desired password file as a hex string or regular string
# ^ ASCIIbutRepresentedAsHex: Each char pair in desired password file must be from 00 to 7F (i.e., 0 to 127)
USE_RANDOM_GUESS = False # True: Use random guesses for the password. False: Use sequential guesses for the password.
NUM_CHARS_IN_PW = 1		 # value N. E.g., pw="Hello" => NUM_CHARS_IN_PW==len("Hello")==5.
# ^ if NUM_CHARS_IN_PW < actualPwLen, it'll take longer, but you'll get the correct pw eventually.
# ^ if NUM_CHARS_IN_PW > actualPwLen, you'll never get the correct pw because it will have been skipped.


def timer(func):
    def wrapper_timer(*args, **kwargs):
        tic = perf_counter_ns()
        # tic = time_ns()
        value = func(*args, **kwargs)
        toc = perf_counter_ns()
        # toc = time_ns()
        elapsed_time = toc - tic
        print(f"Elapsed time for {func.__name__}(): {(elapsed_time/1E9):0.4f} seconds")
        return value
    return wrapper_timer


# Generate passwords to break (pws that I can put in pwFile.txt or saltedPwFile.txt, along with their salts, if used)
def generateNewHashes():
	print("Hash generator (using known salts and known passwords):")
	print("<> ENSURE THAT, WHEN COPYING RESULTS FROM THIS FUNCTION, YOU COPY ALL CHARACTERS OF THE HASH.")
	print("<> BEWARE OF WORD WRAP. SHA-256 WILL LIKELY GENERATE 64-BYTE (64 chars long) HASHES")
	pws = ["0","1","2","d4","**","tri","myPw"]	# Plain ASCII
	salts = []
	if USE_HEX_SALT:
		print("--Assuming salts in pw file are ASCII values that are hex-encoded")
		salts = ["7F7f", "00", "12", "4e69636553616c7421", "030405060708090A0B0C0D0E0F", "030405060708090A0B0C0D0E0F", "1234567809"]
	elif USE_SALT:
		print("--Assuming salts in pw file are ASCII values")
		salts = ["7F7f", "0", "12", "4e69636553616c7421", "NiceSalt!", "NiceSalt!", "123456789"]	# Plain ASCII
	if USE_SALT or USE_HEX_SALT:
		assert len(pws) == len(salts)

	for i in range( len(pws) ):
		tmp = f"{pws[i]}".encode("utf-8")
		if USE_HEX_SALT:
			# strWithHexContent => ByteStrWithASCIIcontent => StrWithASCIIcontent
			asciiSalt = bytes.fromhex(salts[i]).decode("utf-8")
			tmp = f"{pws[i]}{asciiSalt}".encode("utf-8")
		elif USE_SALT:
			tmp = f"{pws[i]}{salts[i]}".encode("utf-8")
		
		# Hashing function only accepts byte strings, meaning tmp must be a byte string (must be encode()d)
		tmp2 = SHA256.new(tmp).hexdigest()
		if USE_SALT or USE_HEX_SALT:
			print(f"> hash(\"{pws[i]}\" || \"{salts[i]}\") ==",tmp2)
		else:
			print(f"> hash(\"{pws[i]}\") ==",tmp2)
	print("\n")


def getRandomWord(possibleChars, numCharsInWord):
	return ''.join(random.choice(possibleChars) for i in range(numCharsInWord))

############################################################################################################################################################
# JFMoya's answer: https://stackoverflow.com/questions/29351492/how-to-make-a-continuous-alphabetic-list-python-from-a-z-then-from-aa-ab-ac-e (found on Nov 24, 2024)
def getSequentialWordUsingIdx(possibleChars, numTermInTheEntireSeries):
	# This is just counting numbers like a binary counter or regular clock, but instead of base 2 or base 60 or base 10, it's base `len(possibleChars)`
	indices = []
	n = numTermInTheEntireSeries
	# n CANNOT BE 0 BECAUSE while LOOP WILL NEVER EXECUTE, MEANING `return ""`
	if n==0:
		print("\nERROR:  Function getSequentialWordUsingIdx(numTermInTheEntireSeries) was called incorrectly. Attempted to be access 0th term.\n")
	
	numPossibleChars = len(possibleChars)
	while n:
		residual = n % numPossibleChars
		if residual == 0:
			residual = numPossibleChars
		indices.append(residual)
		n -= residual
		n = n // numPossibleChars
	indices.reverse()
	word = ""
	for i in indices:
		word += possibleChars[i-1]
	return word


def getSequentialWordUsingExactLen(possibleChars, exactNumCharsInWord, numTermInTheSeries):
	# numCharsInWord = 2
	# numPossibleChars to the numChars power == totalNumPermutations (from strLen=0 up to a given string length)
	# numWordsOfSpecificLength = len(possibleChars)**numCharsInWord
	# numWordsOfSpecificLengthMinus1 = len(possibleChars)**(numCharsInWord-1)
	#
	# Below line is WRONG because doesn't account for strings with even fewer chars than `numCharsInWord-1`
	# numWordsWithExactLength = (len(possibleChars)**numCharsInWord) - (len(possibleChars)**(numCharsInWord-1))

	maxNumCharsInWord = exactNumCharsInWord
	# [1 char has len(lang) possibilities, 2 chars has len(lang)^2 possibilities, 3 chars has len(lang)^3 possibilities, ...]
	# E.g., if using lang=lowercaseASCII: exactly 1 char has 26 possibilities, exactly 2 chars has 26^2 possibilities, exactly 3 chars has 26^3 possibilities
	numWordsOfSpecificLength_list = [0]	# Because there are 0 words you can produce using 0 chars
	for i in range(1,maxNumCharsInWord+1):
		numWordsWithExactly_i_chars = len(possibleChars)**i
		numWordsOfSpecificLength_list.append(numWordsWithExactly_i_chars)
	# There are numWordsOfSpecificLength_list[3] possible words with length exactly 3

	# sumOfNumWordsUpToSpecificLength = sum(numWordsOfSpecificLength_list[:maxNumCharsInWord+1])	# == sum(list[:])
	sumOfNumWordsUpTo_SpecificLengthMinus1 = sum(numWordsOfSpecificLength_list[:maxNumCharsInWord])	# == sum(list[allExceptLastElement])
	# if DEBUG:
		# print(numWordsOfSpecificLength_list)			# E.g., [68, 4624, 314432]
		# print(sumOfNumWordsUpToSpecificLength)		#       319124  (== 68+4624+314432)
		# print(sumOfNumWordsUpTo_SpecificLengthMinus1)	#       4692    (== 68+4624)

		# Print all words in the given alphabet from length=0 to length=numCharsInWord
		# for numOfTerm in range(1, sumOfNumWordsUpToSpecificLength+1):
		# 	print(getSequentialWordUsingIdx(numOfTerm))

		# Print all words in the given alphabet with length=numCharsInWord.
		# for numOfTerm in range(sumOfNumWordsUpTo_SpecificLengthMinus1+1, sumOfNumWordsUpToSpecificLength+1):
		# 	print(getSequentialWordUsingIdx(numOfTerm))
	
	return getSequentialWordUsingIdx(possibleChars, sumOfNumWordsUpTo_SpecificLengthMinus1 + numTermInTheSeries)	# i.e., getWord(baseIdx+offset)
############################################################################################################################################################




# Password File Requirements:
# > The plaintext password is NOT included.
# > There are no empty lines in the file.
# > * Extra newlines make the program think there's another user, but with no user date.
# > Either Every record (row) has a salt, or Every record does NOT have a salt, not both cases.
# > Records are separated by a single newline character.
# > Salts, if used, contain only hexadecimal values (no emojis, ASCII, unicode, etc).
# >>> This isn't for a great reason, I just chose it to be that way.
# > Hashes contain only hexadecimal values (no emojis, ASCII, unicode, etc).
# >>> E.g., "ff3" is okay, but "ffg" is not okay.
# > Each row element within a single row is separated by at least one space.
# > Single quotes (') and double quotes (") must NOT be present in the file.
# >>> This isn't for a great reason, I just chose it to be that way.
# > Square brackets ([]) and commas (,) are unnecessary, but can be added if desired.
# > Column alignment using extra whitespace to make all rows look pretty is unnecessary.
""" Two examples of good password files ([user,salt,hash], notice the password itself isn't listed):
PwFile1:
[username10,     7F7f,               be90a88fc27d1ae26fc9434cede0548dbd557ffbd093ad748d2e551868d11663]
[username200,    00,                 e79e418e48623569d75e2a7b09ae88ed9b77b126a445b9ff9dc6989a08efa079]
[username4,      12,                 ed4253cc34b91e95debe5ca6c97d434dcefed2e9ce8402b1874286aabbc40e5d]
[username3000,   4e69636553616c7421,          e4be1c4ae0179d489ad85eeaeba402d675200b06338e1ebd29deb5973cb33d99]
[username50000,  030405060708090A0B0C0D0E0F,  c91ec44ec1959bd6f6bc2f996b2cc531fba72ec6544379107edd9c4d3d945209]
[username600000, 030405060708090A0B0C0D0E0F,  e927d3feb001beec148981d043322423627aa5deb6f015ad1bbfb0301a816362]
[username700000, 1234567809,                  128cb981e258ff9f60153122ab5a7a3c0901b7cfb53c259c28055d16b7929a61]


PwFile2:
[username10,   7F7f,  7267b54c0af471df0c9360c0da086f50df7d1e5d8bfd253c0659e82369e38586]
[username200,  0,         4a44dc15364204a80fe80e9039455cc1608281820fe2b24f1e5233ade6af1dd5]
[username4, 12, fa2b7af0a811b9acde602aacb78e3638e8506dfead5fe6c3425b10b526f94bdd]
[username3000, 4e69636553616c7421, c9ec37c1fb09da26327de44efcbca6389f7f05f047d9ac87afc53b80c055dd40]


[username50000,    NiceSalt!,      922a37e7817fffd788e7e433584001a16d464ce96f21d270bded11e265f8d0ca]
[username600000,   NiceSalt!,  39d7c88e7fef1ae51ded3938560dcb2e589bb3b63f789f52ae904d4c0f94e48d]

[username700000,  123456789,      dccb55acddfb58b2c534a3ca25bdc6598918c4caace65808bf23c35b7599b5fa]


"""
def readPasswordFile(filename):
	userPwPairs = []
	with open(filename, "r") as f:
		fileContents = f.read()
		print(f"Password File {filename}'s contents[\n"+fileContents+"\n]")
		
		# Each line (row) is an element. Each row is "user   pw"
		# Ex input: 'Steve 123\nMoma     456\nYerr  7890'
		# Ex result: ['Steve 123', 'Moma     456', 'Yerr  7890']

		# Get rid of the brackets and commas if the pwFile has them. I don't use/parse commas, I just use spaces and newlines.
		import re	# Regular Expressions
		# Remove square brackets and commas
		charsToRemove_regEx = r"[\[\],]"
		fileContents1 = re.sub(charsToRemove_regEx, '', fileContents)
		
		# Remove extra newlines (any place where there is >1 newline char)
		# The regex expression replaces multiple contiguous newline characters with a single newline character
		fileContents2 = re.sub("[\n]+", '\n', fileContents1)

		# Remove trailing newline (or other whitespace)
		fileContents3 = fileContents2.strip()
		if DEBUG:
			print("Password File's filtered contents{\n"+fileContents3+"\n}")

		# Create list
		rows = fileContents3.split("\n")

		for row in rows:
			# Split row into words and spaces
			# ["User", [,"salt"], "hashedPw"] (with possible spaces as elements in between words)(inner brackets represent a possible extra, not a list)
			# Ex input: 'Moma     456'
			# Ex result: ['Moma',' ',' ',' ',' ',' ','456']
			elementsInSingleRow = row.split(" ")

			# Delete extra whitespace
			desiredRow = []
			for element in elementsInSingleRow:
				# https://www.geeksforgeeks.org/python-ways-to-remove-multiple-empty-spaces-from-string-list/
				# if charsAreLeftOverAfterRemovingWhitespace:
				if element.strip():
					desiredRow.append(element)
			
			# Add correctly formatted row to main list
			userPwPairs.append(desiredRow)
		# E.g., userPwPairs=[['Steve','123'], ['Moma','456'], ['Yerr','7890']]
		# print(userPwPairs)
	
	# if there's at least one record (at least 1 row that contains at least user+pw)
	if len(userPwPairs) > 0:
		numItemsPerRecord = len(userPwPairs[0])
		return [userPwPairs, numItemsPerRecord]
	else:
		return [None, 0]
# if pwFile doesn't store salts, returns [[[username1, password1], [u2, pw2], [u3, pw3], ...], numItemsInEachRecord=2]
# if pwFile stores salts , returns [[[username1, salt1, password1], [u2, s2, pw2], [u3, s3, pw3], ...], numItemsInEachRecord=3]
# numItemsPerRecord tells you whether (index 1 is a salt and index 2 is a hashed pw) or (there is no salt and index 1 is the hashed pw)

def displayPwLenError(currLen):
	print(f"\nA matching pw with length {currLen} for any of the remaining unsolved users with [given alphabet/language] and [given pw length ({NUM_CHARS_IN_PW})] does not exist.")
	print("Trying longer passwords...\n")


# Unsalted SUMMARY
# Take the file's hashed passwords,
# add them to a list of hashesOfUnknownPws,
# guess a random pw (randomPw), check the list of alreadyGuessedPws (discoveredHashes) to ensure you haven't already guessed it,
#   If randomPw hasn't been guessed before, hash randomPw, and check the entirety of hashesOfUnknownPws for randomPw_hashed
# Repeat above two lines until you find a matching pwHash (ie stop when randomPw_hashed == hashesOfUnknownPws[i])
# Print out randomPw (that produced randomPw_hashed) and corresponding user

# Salted SUMMARY
# Take the file's hashed passwords,
# add them to a list of hashesOfUnknownPws,
# take the file's salts,
# add them to a list of userSalts,
# guess a random pw (randomPw), check the list of alreadyGuessedPws (discoveredHashes) to ensure you haven't already guessed it,
#   If randomPw hasn't been guessed before, iterate over the entire list of salts,
#     for each salt, hash randomPw, and check the entirety of hashesOfUnknownPws for randomPw_hashed
# Repeat above three lines until you find a matching pwHash (ie stop when randomPw_hashed == hashesOfUnknownPws[i])
# Print out randomPw (that helped produce randomPw_hashed) and corresponding user and salt



@timer	# Decorator for function
def main():
	# Initialize variables before loop
	possibleChars = string.digits + string.ascii_lowercase + string.ascii_uppercase + "#$%^&*"
	totalNumTrials = 0
	totalTimeNs = 0
	discoveredHashes   = {}		# Create dictionary
	hashesOfUnknownPws = set()	# Create set
	userSalts = set()
	successfulMatches = []	# Will contain list of [username, pw, saltIfUsed, hash]
	matchFound = False
	userPwPairs = []
	#
	# I don't care about numItemsPerRecord, but it might be useful to a future developer
	if not USE_SALT:
		userPwPairs, numItemsPerRecord = readPasswordFile("pwFile.txt")
	elif USE_HEX_SALT:
		userPwPairs, numItemsPerRecord = readPasswordFile("hexSaltedPwFile.txt")
	elif USE_SALT:
		userPwPairs, numItemsPerRecord = readPasswordFile("saltedPwFile.txt")
	NUM_PW_TO_BREAK = len(userPwPairs)
	assert (NUM_PW_TO_BREAK != 0)
	# E.g., userPwPairs=[['Steve','123'], ['Moma','456'], ['Yerr','7890']]
	# E.g., discoveredHashes={'123':"7Dy4$",  '987':"fhgY#%",  'Pw123':"aa%^qqR2"}

	generateNewHashes()

	# Add all file's hashed passwords to a set of hashesOfUnknownPws.
	# Add all file's salts to a set of userSalts.
	for user_pw in userPwPairs:
		if len(user_pw) > 1:
			hash = user_pw[1]
			if USE_SALT:
				salt = user_pw[1]
				userSalts.add(salt)
				hash = user_pw[2]
			
			hashesOfUnknownPws.add(hash)
		else:
			print("MAJOR ERROR: UserPwPair missing at least one element")


	#############
	# MAIN LOOP #
	#############
	while hashesOfUnknownPws:	# while the set isn't empty
		# Initialize variables
		correctPw = ""
		correctSalt = ""
		correctHash = ""
		numTrialsForThisHash = 0
		pwLenErrHasBeenDisplayed = False	# Flag that gets flipped once
		prevRandPw = "0"					# Only used for printing "no remaining pws of this length were useful" by finding boundaries of pwLens. E.g., prev="99", curr="000"
		startTime = time_ns()


		while not matchFound:

			if (not USE_SALT) and (not USE_HEX_SALT):	# if hashOnlyThePassword
				randPw = getRandomWord(possibleChars, NUM_CHARS_IN_PW)	# if USE_RANDOM_GUESS
				if not USE_RANDOM_GUESS:								# if USE_SEQUENTIAL_GUESS
					if totalNumTrials > 0:
						prevRandPw = getSequentialWordUsingExactLen(possibleChars, exactNumCharsInWord=NUM_CHARS_IN_PW, numTermInTheSeries=totalNumTrials)
					randPw = getSequentialWordUsingExactLen(possibleChars, exactNumCharsInWord=NUM_CHARS_IN_PW, numTermInTheSeries=totalNumTrials+1)
					# if haveNotAlreadyDisplayedError AND pwLenIsUnexpected
					#    AND ALL_notJustSome_pwsOfCertainLenHaveBeenGuessed:  printError(PwLenIsWrong)
					if (not pwLenErrHasBeenDisplayed) and (len(randPw) != NUM_CHARS_IN_PW) and (len(randPw) != len(prevRandPw)):
						pwLenErrHasBeenDisplayed = True
						displayPwLenError( len(randPw)-1 )
				if DEBUG:
					print(f"UNSALTED GENERATION:  Randomly guessed pw: {randPw}.  total#trials: {totalNumTrials}")
				hashOfRandPw = SHA256.new(randPw.encode("utf-8")).hexdigest()

				# If randomPw hasn't been guessed before, hash randomPw, and check the entirety of hashesOfUnknownPws for randomPw_hashed
				if hashOfRandPw in hashesOfUnknownPws:		# if randomlyGeneratedHash is in the set of userPwHashes
					hashesOfUnknownPws.remove(hashOfRandPw)	# Since we now know the corresponding pw to the hash, no longer need to search for it

					correctPw = randPw
					correctHash = hashOfRandPw

					# Find user who has matching hash
					for userInfo_exceptPw in userPwPairs:
						if (len(userInfo_exceptPw) < 2):
							print("UNBELIEVABLY MAJOR ERROR: UserPwPair missing a hash")
						else:
							username = userInfo_exceptPw[0]
							hashFromUserPw = userInfo_exceptPw[1]
							
							if hashOfRandPw == hashFromUserPw:
								print(f"!!!!!!!!!!!!!!!!!!!!!!!!\nFound match:\n> Randomly guessed pw:            {randPw}")
								print(f"> User's salt:                    None")
								print(f"> Full hash of randomlyGuessedPw: {hashOfRandPw}")
								print(f"> User's full hash:               {hashFromUserPw}")
								print(f"> User:                           {username}\n!!!!!!!!!!!!!!!!!!!!!!!!")
								successfulMatches.append([username, randPw, hashFromUserPw])
								matchFound = True
								# Don't `break` out of innermost for loop because multiple users could have the same pw (and therefore also have the same hash)
				else:
					if DEBUG:
						print("randomlyGeneratedHash is NOT in the set of userPwHashes")
						print(f"> Randomly guessed pw:            {randPw}")
						print(f"> Full hash of randomlyGuessedPw: {hashOfRandPw}\n")
						# There's no salt nor username to print here because there were no matches.
					
				
				# Insert msg:hash pair into dictionary AFTER searching the dictionary
				#   for matching hashes, regardless of whether there was a match in
				#   the dictionary or not
				discoveredHashes[randPw] = hashOfRandPw
				if DEBUG:	print(f"INFO:  Added  {randPw}:{hashOfRandPw}  to dictionary discoveredHashes\n")
			# Unsalted
			###########################################################################################################################################
			# Salted
			else:	# if USE_SALT:
				randPw = getRandomWord(possibleChars, NUM_CHARS_IN_PW)	# if USE_RANDOM_GUESS
				if not USE_RANDOM_GUESS:				# if USE_SEQUENTIAL_GUESS
					if totalNumTrials > 0:
						prevRandPw = getSequentialWordUsingExactLen(possibleChars, exactNumCharsInWord=NUM_CHARS_IN_PW, numTermInTheSeries=totalNumTrials)
					randPw = getSequentialWordUsingExactLen(possibleChars, exactNumCharsInWord=NUM_CHARS_IN_PW, numTermInTheSeries=totalNumTrials+1)
					# if haveNotAlreadyDisplayedError AND pwLenIsUnexpected
					#    AND ALL_notJustSome_pwsOfCertainLenHaveBeenGuessed:  printError(PwLenIsWrong)
					if (not pwLenErrHasBeenDisplayed) and (len(randPw) != NUM_CHARS_IN_PW) and (len(randPw) != len(prevRandPw)):
						pwLenErrHasBeenDisplayed = True
						displayPwLenError( len(randPw)-1 )
				if DEBUG:
					print(f"SALTED GENERATION:  Randomly guessed pw: {randPw}.  total#trials: {totalNumTrials}")
				
				# Try all userSalts (for each randomly guessed pw) when making a hash
				for salt in userSalts:	# THIS IS A NEW LOOP, MAKING EVERYTHING TAKE LONGER BY A FACTOR OF numUserSalts (approx == numUsers)
					pwToBeHashed = randPw+salt	# Append the salt string to the pw before hashing
					if USE_HEX_SALT:
						# strWithHexContent => ByteStrWithASCIIcontent => StrWithASCIIcontent
						pwToBeHashed = randPw + (bytes.fromhex(salt).decode("utf-8"))

					hashOfRandPw = SHA256.new(pwToBeHashed.encode("utf-8")).hexdigest()

					# If randomPw hasn't been guessed before, hash randomPw, and check the entirety of hashesOfUnknownPws for randomPw_hashed
					if hashOfRandPw in hashesOfUnknownPws:		# if randomlyGeneratedHash is in the set of userPwHashes
						hashesOfUnknownPws.remove(hashOfRandPw)	# Since we now know the corresponding pw to the hash, no longer need to search for it

						correctPw = randPw
						correctSalt = salt
						correctHash = hashOfRandPw

						# Find user who has matching hash
						for userInfo_exceptPw in userPwPairs:
							if (len(userInfo_exceptPw) < 2):
								print("UNBELIEVABLY MAJOR ERROR: UserPwPair missing a hash and a salt")
							elif (len(userInfo_exceptPw) < 3):
								print("UNBELIEVABLY MAJOR ERROR: UserPwPair missing a salt")
							else:
								username = userInfo_exceptPw[0]
								salt     = userInfo_exceptPw[1]
								hashFromSaltedPwOfUser = userInfo_exceptPw[2]
								
								if hashOfRandPw == hashFromSaltedPwOfUser:
									print(f"\n!!!!!!!!!!!!!!!!!!!!!!!!\nFound match:\n> Randomly guessed pw:            {randPw}")
									print(f"> User's salt:                    {salt}")
									print(f"> Full hash of randomlyGuessedPw: {hashOfRandPw}")
									print(f"> User's full hash:               {hashFromSaltedPwOfUser}")
									print(f"> User:                           {username}\n!!!!!!!!!!!!!!!!!!!!!!!!")
									successfulMatches.append([username, randPw, salt, hashFromSaltedPwOfUser])
									matchFound = True
									# Don't `break` out of innermost for loop because multiple users could have the same pw (and therefore also have the same hash)
					else:
						if DEBUG:
							print("randomlyGeneratedHash is NOT in the set of userPwHashes")
							print(f"> Randomly guessed pw:            {randPw}")
							print(f"> Salt appended to pw:            {salt}")
							print(f"> Full hash of randomlyGuessedPw: {hashOfRandPw}\n")
							# There's no username to print here because there were no matches.
						
					
					# Insert msg:hash pair into dictionary AFTER searching the dictionary
					#   for matching hashes, regardless of whether there was a match in
					#   the dictionary or not
					discoveredHashes[(randPw,salt)] = hashOfRandPw
					if DEBUG:	print(f"INFO:  Added  ({randPw}, {salt}):{hashOfRandPw}  to dictionary discoveredHashes\n")
			
			numTrialsForThisHash += 1
			totalNumTrials += 1
		# A single match has now been found.
		endTime = time_ns()
		totalTimeNs += (endTime-startTime)
		print(f"Discovered after {(totalTimeNs/1E9):0.4f} seconds\n")

		if DEBUG:
			info ="Time (seconds) to find this collision (pw): " + str((endTime-startTime)/1E9)\
				+ "\nPw that produces collision:            " + correctPw
			if USE_SALT:
				info += "\nSalt used to create the hash:          " + salt
			info+="\nHash of (pw that produces collision):  " + correctHash\
				+ "\nnumTrials to find this collision (pw): " + str(numTrialsForThisHash)
			print(info, "\n")
		matchFound = False
		# totalNumTrials += numTrialsForThisHash	# I do it one-at-a-time, making this line unnecessary
	print(f"totalNumTrials for {NUM_PW_TO_BREAK} collisions (pws):", totalNumTrials)
	print(f"avgNumTrials: {(totalNumTrials/NUM_PW_TO_BREAK):0.4f}")
	print(f"Total time (seconds) to break all {NUM_PW_TO_BREAK} passwords: {(totalTimeNs/1E9):0.4f}")
	print(f"Avg time (seconds) to break each password: {(totalTimeNs/NUM_PW_TO_BREAK/1E9):0.4f}")

	print("\nSuccessfully Broken Passwords:")
	if (not USE_SALT) and (not USE_HEX_SALT):
		print("Format: ['username', 'password', 'hash']")
	else:
		print("Format: ['username', 'password', 'salt', 'hash']")
	for match in successfulMatches:
		print(">",match)

main()

# How to improve in future:
# Change  getRandomWord( len(knownPlaintext) ) to
#   Iterate over a dictionary file of English words and leetcode permutations
#	  like e=>3, i=>1