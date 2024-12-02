from Crypto.Hash import SHA256
from time import perf_counter_ns, time_ns
import string	# For getRandomWord() and getSequentialWordUsingIdx() and getSequentialWordUsingExactLen()
import random	# For getRandomWord()


# DEBUG = True
USE_SALT = False			# Should match whether desired password file uses regular ASCII salts.
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


possibleChars = string.digits + string.ascii_lowercase + string.ascii_uppercase + "#$%^&*"

def getRandomWord(numCharsInWord):
	return ''.join(random.choice(possibleChars) for i in range(numCharsInWord))

############################################################################################################################################################
def getSequentialWordUsingIdx(n):
	indices = []
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


def getSequentialWordUsingExactLen(exactNumCharsInWord, numTermInTheSeries):
	numWordsOfSpecificLength_list = [0]
	for i in range(1,exactNumCharsInWord+1):
		numWordsWithExactly_i_chars = len(possibleChars)**i
		numWordsOfSpecificLength_list.append(numWordsWithExactly_i_chars)
	sumOfNumWordsUpTo_SpecificLengthMinus1 = sum(numWordsOfSpecificLength_list[:exactNumCharsInWord])	# == sum(list[allExceptLastElement])
	return getSequentialWordUsingIdx(sumOfNumWordsUpTo_SpecificLengthMinus1 + numTermInTheSeries)	# i.e., getWord(baseIdx+offset)
############################################################################################################################################################




# Password File Requirements:
# > The plaintext password is NOT included.
# > There are no empty lines in the file.
# > * Extra newlines make the program think there's another user, but with no user date.
# > Either Every record (row) has a salt, or Every record does NOT have a salt, not both cases.
# > Records are separated by a single newline character.
# > Hex-encoded ASCII Salts, if used, must contain only hexadecimal value pairs between 00 and 7F
# > * I.e., 0 to 127, and no emojis, no human-readable ASCII, no unicode, no single letters/numbers, etc.
# > * Feature that allows storage of unprintable ASCII characters as salts in the pw file.
# > Hash values ("hashes") contain only hexadecimal value pairs (no emojis, ASCII, unicode specials, etc).
# > * E.g., "ff00" is okay, but "fg" and "f" are not okay because they contain a non-hex value and a non-pair respectively.
# > * Realistically, your hash value should be at the very very least 8 bytes long, not a very insecure byte or two.
# > * If you're getting hex hashes but they don't already fit this format, something is VERY wrong with your hash function and you need to stop using it.
# > * If you're getting hash values with weird symbols like a heart or emoji, convert the hashes to hex.
# > Each row element within a single row is separated by at least one space.
# > Single quotes (') and double quotes (") must NOT be present in the file.
# > * This isn't for a great reason, I just chose it to be that way.
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
		# if DEBUG:
		#	 print(f"Password File {filename}'s contents[\n"+fileContents+"\n]")

		import re	# Regular Expressions
		charsToRemove_regEx = r"[\[\],]"
		fileContents1 = re.sub(charsToRemove_regEx, '', fileContents)
		fileContents2 = re.sub("[\n]+", '\n', fileContents1)
		fileContents3 = fileContents2.strip()

		rows = fileContents3.split("\n")	# Create list

		for row in rows:
			elementsInSingleRow = row.split(" ")
			desiredRow = []
			for element in elementsInSingleRow:
				if element.strip():	# if charsAreLeftOverAfterRemovingWhitespace:
					desiredRow.append(element)
			
			userPwPairs.append(desiredRow)	# Add correctly formatted row to main list
	
	if len(userPwPairs) > 0:
		return [userPwPairs, len(userPwPairs[0])]
	else:
		return [None, 0]
# if pwFile doesn't store salts, returns [[[username1, password1], [u2, pw2], [u3, pw3], ...], numItemsInEachRecord=2]
# if pwFile stores salts , returns [[[username1, salt1, password1], [u2, s2, pw2], [u3, s3, pw3], ...], numItemsInEachRecord=3]
# numItemsPerRecord tells you whether (index 1 is a salt and index 2 is a hashed pw) or (there is no salt and index 1 is the hashed pw)


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


@timer
def main():
	# Initialize variables before loop
	totalNumTrials = 0
	totalTimeNs = 0
	discoveredHashes   = {}		# Create dictionary
	hashesOfUnknownPws = set()	# Create set
	userSalts = set()
	successfulMatches = []	# Will contain list of [username, pw, saltIfUsed, hash]
	matchFound = False
	userPwPairs = []
	#
	if not USE_SALT:
		userPwPairs, numItemsPerRecord = readPasswordFile("pwFile.txt")
	elif USE_HEX_SALT:
		userPwPairs, numItemsPerRecord = readPasswordFile("hexSaltedPwFile.txt")
	elif USE_SALT:
		userPwPairs, numItemsPerRecord = readPasswordFile("saltedPwFile.txt")
	NUM_PW_TO_BREAK = len(userPwPairs)
	assert (NUM_PW_TO_BREAK != 0)

	generateNewHashes()


	# Add all file's hashed passwords to a set of hashesOfUnknownPws.
	# Add all file's salts to a set of userSalts.
	for user_pw in userPwPairs:
		hash = user_pw[1]
		if USE_SALT or USE_HEX_SALT:
			salt = user_pw[1]
			userSalts.add(salt)
			hash = user_pw[2]
		
		hashesOfUnknownPws.add(hash)


	#############
	# MAIN LOOP #
	#############
	while hashesOfUnknownPws:	# while the set isn't empty
		# correctPw = ""
		# correctSalt = ""
		# correctHash = ""
		numTrialsForThisHash = 0
		startTime = time_ns()


		while not matchFound:

			if (not USE_SALT) and (not USE_HEX_SALT):	# if hashOnlyThePassword
				randPw = getRandomWord(NUM_CHARS_IN_PW)	# if USE_RANDOM_GUESS
				if not USE_RANDOM_GUESS:				# if USE_SEQUENTIAL_GUESS
					randPw = getSequentialWordUsingExactLen(exactNumCharsInWord=NUM_CHARS_IN_PW, numTermInTheSeries=totalNumTrials+1)
				# if DEBUG:
				# 	print(f"\n\nUNSALTED GENERATION:  Randomly guessed pw: {randPw}.  total#trials: {totalNumTrials}\n")
				hashOfRandPw = SHA256.new(randPw.encode("utf-8")).hexdigest()

				# If randomPw hasn't been guessed before, hash randomPw, and check the entirety of hashesOfUnknownPws for randomPw_hashed
				if hashOfRandPw in hashesOfUnknownPws:		# if randomlyGeneratedHash is in the set of userPwHashes
					hashesOfUnknownPws.remove(hashOfRandPw)	# Since we now know the corresponding pw to the hash, no longer need to search for it

					# correctPw = randPw
					# correctHash = hashOfRandPw

					# Find user who has matching hash
					for userInfo_exceptPw in userPwPairs:
						username = userInfo_exceptPw[0]
						hashFromUserPw = userInfo_exceptPw[1]
						
						if hashOfRandPw == hashFromUserPw:
							# if DEBUG: print("\n\n\n\n")
							print(f"\n!!!!!!!!!!!!!!!!!!!!!!!!\nFound match:\n> Randomly guessed pw:            {randPw}")
							print(f"> User's salt:                    None")
							print(f"> Full hash of randomlyGuessedPw: {hashOfRandPw}")
							print(f"> User's full hash:               {hashFromUserPw}")
							print(f"> User:                           {username}\n!!!!!!!!!!!!!!!!!!!!!!!!")
							successfulMatches.append([username, randPw, hashFromUserPw])
							matchFound = True
				# else:
				# 	if DEBUG:
				# 		print("randomlyGeneratedHash is NOT in the set of userPwHashes")
				# 		print(f"> Randomly guessed pw:            {randPw}")
				# 		print(f"> Full hash of randomlyGuessedPw: {hashOfRandPw}\n")
				discoveredHashes[randPw] = hashOfRandPw
			# Unsalted
			###########################################################################################################################################
			# Salted
			else:
				randPw = getRandomWord(NUM_CHARS_IN_PW)
				if not USE_RANDOM_GUESS:
					randPw = getSequentialWordUsingExactLen(exactNumCharsInWord=NUM_CHARS_IN_PW, numTermInTheSeries=totalNumTrials+1)
				# if DEBUG:
				# 	print(f"\n\nSALTED GENERATION:  Randomly guessed pw: {randPw}.  total#trials: {totalNumTrials}\n")
				
				for salt in userSalts:
					pwToBeHashed = randPw+salt
					if USE_HEX_SALT:
						# strWithHexContent => ByteStrWithASCIIcontent => StrWithASCIIcontent
						pwToBeHashed = randPw + (bytes.fromhex(salt).decode("utf-8"))

					hashOfRandPw = SHA256.new(pwToBeHashed.encode("utf-8")).hexdigest()

					if hashOfRandPw in hashesOfUnknownPws:
						hashesOfUnknownPws.remove(hashOfRandPw)	# Since we now know the corresponding pw to the hash, no longer need to search for it

						# correctPw = randPw
						# correctSalt = salt
						# correctHash = hashOfRandPw

						# Find user who has matching hash
						for userInfo_exceptPw in userPwPairs:
							username = userInfo_exceptPw[0]
							salt     = userInfo_exceptPw[1]
							hashFromSaltedPwOfUser = userInfo_exceptPw[2]
							
							if hashOfRandPw == hashFromSaltedPwOfUser:
								# if DEBUG: print("\n\n\n\n")
								print(f"!!!!!!!!!!!!!!!!!!!!!!!!\nFound match:\n> Randomly guessed pw:            {randPw}")
								print(f"> User's salt:                    {salt}")
								print(f"> Full hash of randomlyGuessedPw: {hashOfRandPw}")
								print(f"> User's full hash:               {hashFromSaltedPwOfUser}")
								print(f"> User:                           {username}\n!!!!!!!!!!!!!!!!!!!!!!!!")
								successfulMatches.append([username, randPw, salt, hashFromSaltedPwOfUser])
								matchFound = True
					# else:
					# 	if DEBUG:
					# 		print("randomlyGeneratedHash is NOT in the set of userPwHashes")
					# 		print(f"> Randomly guessed pw:            {randPw}")
					# 		print(f"> Salt appended to pw:            {salt}")
					# 		print(f"> Full hash of randomlyGuessedPw: {hashOfRandPw}\n")
					discoveredHashes[(randPw,salt)] = hashOfRandPw
			
			numTrialsForThisHash += 1
			totalNumTrials += 1
		endTime = time_ns()
		totalTimeNs += (endTime-startTime)
		print(f"Discovered after {(totalTimeNs/1E9):0.4f} seconds\n")

		# if DEBUG:
		# 	info ="Time (seconds) to find this collision (pw): " + str((endTime-startTime)/10E9)\
		# 		+ "\nPw that produces collision:            " + correctPw
		# 	if USE_SALT:
		# 		info += "\nSalt used to create the hash:          " + salt
		# 	info+="\nHash of (pw that produces collision):  " + correctHash\
		# 		+ "\nnumTrials to find this collision (pw): " + str(numTrialsForThisHash)
		# 	print(info, "\n")
		matchFound = False
	print(f"totalNumTrials for {NUM_PW_TO_BREAK} collisions (pws):", totalNumTrials)
	print(f"> avgNumTrials: {(totalNumTrials/NUM_PW_TO_BREAK):0.4f}")
	print(f"Total time (seconds) to break all {NUM_PW_TO_BREAK} passwords: {(totalTimeNs/1E9):0.4f}")
	print(f"> Avg time (seconds) to break each password: {(totalTimeNs/NUM_PW_TO_BREAK/1E9):0.4f}")
	
	print("\nSuccessfully Broken Passwords:")
	if (not USE_SALT) and (not USE_HEX_SALT):
		print("Format: ['username', 'password', 'hash']")
	else:
		print("Format: ['username', 'password', 'salt', 'hash']")
	for match in successfulMatches:
		print(">",match)

main()