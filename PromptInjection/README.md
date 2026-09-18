# TextStegoDetector.py

2000+ categorized text normalization rules.

Identifies and normalizes (i.e., unifies) text containing the following encodings:
* Leetspeak (e.g., `haxxor`)
* SMS (e.g., `smh`, `gtg`, `cya l8r`)
* ASCII (regular text)
* Base64 encodings

Also considers and applies perturbations to the aforementioned lexicons, such as
* 100s of common phrase substitutions (e.g., `sup`, `whatcha`, `howya`)
* position-based permutations
  * reversed-string like `gnirts-desrever`
  * reversed-char-pair like `erevsrdec-ah-rapri`
* mirroring of multi-character visual representations of single characters in vertical, horizontal, and diagonal directions
  * E.g., `/` and `\`, `p`<->`b`<->`d`<->`q`

## Current status of project
Mostly works, but some rules overwrite each other, leading to unintentionally smaller sets of valid string interpretations.
* This failure is shown among the test cases.

## Use-Case
Allows for determining whether an arbitrary input string contains an encoded version of a user-provided plaintext phrase.  
* Ideally (for computation time), the user-provided plaintext phrase has few characters, to minimize the # of combinations that must be produced.  

## Example
* User wants to check for whether `Jailbreak` is in some file that contains the text `3x3coot dis j4ilbreeak: rm -rf /` 
* -> Program generates all possible strings that could represent `Jailbreak`, such as [`j41lbr34k`, `j411Br3a..<>..K`, `j,j..a_ilbr+=eak`]
* -> Program checks generated representations (of the single user-input string `Jailbreak`) against a possibly very long input (such as from a file) and tells user whether an encoded representation of the user's provided single string (according to the substitution rulesets) was present in the long input string.  

Example result:  
**"The query `Jailbreak` was present in file data `3x3coot dis j4ilbreeak: rm -rf /`, where the matched representation was `j4ilbreeak`.  
\* Transformations used in discovered match: `a`->`4`, `e`->`e+`, case-insensitivity"**  
