#!/usr/bin/python

import sys
import optparse
import base64

charToMorse = {'a': '.-','b': '-...','c': '-.-.','d': '-..','e': '.','f': '..-.','g': '--.','h': '....','i': '..','j': '.---','k': '-.-',
	'l': '.-..','m': '--','n': '-.','o': '---','p': '.--.','q': '--.-','r': '.-.','s': '...','t': '-','u': '..-','v': '...-',
	'w': '.--','x': '-..-','y': '-.--','z': '--..','0': '-----','1': '.----','2': '..---','3': '...--','4': '....-','5': '.....',
	'6': '-....','7': '--...','8': '---..','9': '----.', ':': '---...', '.': '.-.-.-', ',': '--..--', '?': '..--..', ')': '-.--.-'
        }
morseToChar = {'.-': 'a','-...': 'b','-.-.': 'c','-..': 'd','.': 'e','..-.': 'f','--.': 'g','....': 'h','..': 'i','.---': 'j','-.-': 'k',
        '.-..': 'l','--': 'm','-.': 'n','---':'o','.--.': 'p','--.-': 'q','.-.': 'r','...': 's','-': 't','..-': 'u','...-': 'v',
        '.--': 'w','-..-': 'x','-.--': 'y','--..': 'z','-----': '0','.----': '1','..---': '2','...--': '3','....-': '4','.....': '5',
        '-....': '6','--...': '7','---..': '8','----.': '9', '---...': ':', '.-.-.-': '.', '--..--': ',', '..--..': '?', '-.--.-': ')'
        }

def encrypt(message):
    morse = ''
    try:
        for c in message:
            if c == ' ':
                morse += ' / '
            else:
                morse += charToMorse[c]+ ' '
        sys.stdout.write(base64.b64encode(morse)+'\n')
    except:
        sys.stdout.write('\nSorry! Character not present, feel free to implement\n')

def decrypt(base64Message):
    morseMessage = base64.b64decode(base64Message)
    print morseMessage
    try:
        for c in morseMessage.split():
            if c == '/':
                sys.stdout.write(' ')
            else:
                sys.stdout.write('{0} '.format(morseToChar[c]))
    except:
        sys.stdout.write('\nPlease use / as a space character')
    sys.stdout.write('\n')
    
def main():
    parser = optparse.OptionParser("usage: %prog  -e <message> -d <message>")
    parser.add_option('-e', dest='encrypt', type='string', help='specify message in clear')
    parser.add_option('-d', dest='decrypt', type='string', help='specify message in base64')
    (options, args) = parser.parse_args()
    encryptMsg = options.encrypt
    decryptMsg = options.decrypt
    if((encryptMsg == None) and (decryptMsg == None)):
        print parser.usage
        exit(0)
    else:
        if encryptMsg:
            encrypt(encryptMsg)
        elif decryptMsg:
            decrypt(decryptMsg)
	
if __name__ == "__main__":
	main()
